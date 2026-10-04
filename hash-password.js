const bcrypt = require('bcryptjs');

function readPassword() {
    return new Promise((resolve, reject) => {
        const stdin = process.stdin;

        if (!stdin.isTTY) {
            reject(new Error('Run this script in an interactive terminal.'));
            return;
        }

        process.stdout.write('New admin password: ');
        stdin.setRawMode(true);
        stdin.resume();
        stdin.setEncoding('utf8');

        let password = '';

        function onData(chunk) {
            for (const char of chunk) {
                if (char === '\u0003') {
                    process.stdout.write('\nCancelled.\n');
                    process.exit(1);
                }

                if (char === '\r' || char === '\n') {
                    stdin.setRawMode(false);
                    stdin.pause();
                    stdin.removeListener('data', onData);
                    process.stdout.write('\n');
                    resolve(password);
                    return;
                }

                if (char === '\u007f') {
                    password = password.slice(0, -1);
                } else {
                    password += char;
                }
            }
        }

        stdin.on('data', onData);
    });
}

(async () => {
    const password = await readPassword();

    if (password.length < 12) {
        throw new Error('Use a password of at least 12 characters.');
    }

    const hash = await bcrypt.hash(password, 12);

    console.log('\nADMIN_PASSWORD_HASH=' + hash);
    console.log('Put this value into Render Environment Variables.');
})();
