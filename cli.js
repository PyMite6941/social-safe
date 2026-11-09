#!/usr/bin/env node
// Node launcher for the social-safe Python package. Works on Windows, macOS, and Linux.
// Finds a Python interpreter that has `socialsafe` installed and runs `python -m socialsafe <args>`.
'use strict';

const { spawnSync, spawn } = require('child_process');
const os = require('os');

const args = process.argv.slice(2);

function candidates() {
  const list = [];
  if (process.env.SOCIALSAFE_PYTHON) list.push([process.env.SOCIALSAFE_PYTHON]);
  if (process.platform === 'win32') {
    list.push(['python'], ['py', '-3'], ['python3']);
  } else {
    list.push(['python3'], ['python']);
  }
  return list;
}

function findPython() {
  let anyPython = null;
  for (const [cmd, ...pre] of candidates()) {
    // Probe from a temp dir so a source checkout in the cwd can't mask a missing install,
    // and import the CLI so missing dependencies are caught too.
    const probe = spawnSync(cmd, [...pre, '-c', 'import socialsafe.cli'], {
      stdio: 'ignore', windowsHide: true, cwd: os.tmpdir(),
    });
    if (probe.error) continue;            // interpreter not found
    anyPython = anyPython || [cmd, ...pre];
    if (probe.status === 0) return { python: [cmd, ...pre], installed: true };
  }
  return { python: anyPython, installed: false };
}

const { python, installed } = findPython();

if (!installed) {
  console.error('social-safe: the Python package is not installed.');
  if (!python) {
    console.error('  No Python 3.10+ interpreter was found. Install Python from https://www.python.org/downloads/');
  }
  const pip = python ? `${python.join(' ')} -m pip` : 'pip';
  console.error(`  Install it with:  ${pip} install git+https://github.com/PyMite6941/social-safe.git`);
  console.error('  Or point SOCIALSAFE_PYTHON at the interpreter that has it installed.');
  process.exit(1);
}

const [cmd, ...pre] = python;
const child = spawn(cmd, [...pre, '-m', 'socialsafe', ...args], { stdio: 'inherit', env: process.env });
child.on('error', (err) => {
  console.error(`social-safe: failed to start ${cmd}: ${err.message}`);
  process.exit(1);
});
child.on('close', (code, signal) => process.exit(signal ? 1 : code));
