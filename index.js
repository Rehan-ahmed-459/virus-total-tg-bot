const Telegraf = require('telegraf');
const vtApi = require('virustotal-api');
const fs = require('fs');

// Set up the Telegraf bot
const bot = new Telegraf(process.env.BOT_TOKEN);

// Set up the VirusTotal API client
const vt = new vtApi(process.env.VT_API_KEY);

// Set up the bot's command
bot.command('scan', (ctx) => {
  // Check if the user sent a file
  if (!ctx.message.document) {
    ctx.reply('Please send me a file to scan.');
    return;
  }

  // Download the file from Telegram
  const fileId = ctx.message.document.file_id;
  const filePath = `${__dirname}/${fileId}.pdf`;
  ctx.telegram.getFileLink(fileId).then((link) => {
    const fileStream = fs.createWriteStream(filePath);
    request(link).pipe(fileStream).on('close', () => {
      // Scan the file with VirusTotal
      vt.fileScan(filePath, (err, res) => {
        if (err) {
          console.error(err);
          ctx.reply('Sorry, something went wrong.');
          return;
        }
        const permalink = res.permalink;
        const positives = res.positives;
        const total = res.total;
        const message = `Scan results: ${positives}/${total} detected. More details at: ${permalink}`;
        ctx.reply(message);
      });
    });
  });
});

// Start the bot
bot.startPolling();
