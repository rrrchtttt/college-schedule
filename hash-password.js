const bcrypt = require('bcryptjs');

const password = process.argv.slice(2).join(' ');

if (!password) {
    console.error('Использование: node hash-password.js "ТВОЙ_ПАРОЛЬ"');
    process.exit(1);
}

bcrypt.hash(password, 12).then(hash => {
    process.stdout.write(hash + "\n");
});
