const { spawn } = require('child_process');
const which = require('which');

// Check if socialsafe-monitor is available in PATH
which('socialsafe-monitor', (err, path) => {
  if (err) {
    console.error('❌ Error: socialsafe-monitor command not found.');
    console.error('   Please install the Python package first:');
    console.error('   pip install git+https://github.com/pymite6941/social-safe.git');
    console.error('   (or use pip install . from the cloned repository)');
    process.exit(1);
  }

  // Spawn the Python monitor process, passing through environment variables
  const monitor = spawn('socialsafe-monitor', [], {
    stdio: 'inherit', // Inherit stdio so we see output and can interact if needed
    env: process.env   // Pass all environment variables to the child process
  });

  monitor.on('close', (code) => {
    process.exit(code);
  });
});