const {Telegraf} = require('telegraf');
const { Extra, Markup } = Telegraf;
const vtApi = require('virustotal-api');
const axios =require('axios');
const fs = require('fs');
const FormData = require('form-data');
const path = require('path');
require('dotenv').config()
// Set up the Telegraf bot
const token=process.env.BOT_TOKEN;
const bot = new Telegraf(`${token}`);

// Set up the VirusTotal API client
const vt = new vtApi(process.env.VIRUSTOTAL_API_KEY);
// Set up the bot's command
bot.command('start', ctx => {
    console.log(ctx.from)
    bot.telegram.sendMessage(ctx.chat.id, 'Hello there! Welcome to Virus Total Bot Created By 0x01Ahmed😎\n\nType /menu to List the Available Commands\n', {
    })
})
bot.command('menu', ctx => {
    console.log(ctx.from)
    bot.telegram.sendMessage(ctx.chat.id, '\n/start - To restart the Bot\n /scan to Scan an File', {
    })
})
bot.command('scan', ctx => {
    console.log(ctx.from)
    bot.telegram.sendMessage(ctx.chat.id, '\nSend a File to Scan📂', {
    })
})



  // Download the file from Telegram
  
  bot.on('document', async (ctx) => {
    const fileId = ctx.update.message.document.file_id;
    const fileUrl = await ctx.telegram.getFileLink(fileId);
  
    const file = await axios.get(fileUrl.href, { responseType: 'stream' });
    const formData = new FormData();
    formData.append('file', file.data);
  
    const headers = {
      'x-apikey': process.env.VIRUSTOTAL_API_KEY,
      ...formData.getHeaders(),
    };
  
    const vtResponse = await axios.post(
      'https://www.virustotal.com/api/v3/files',
      formData,
      {
        headers: headers,
      }
    );
  
    const resourceId = vtResponse.data.data.id;
    const analysisUrl = `https://www.virustotal.com/api/v3/analyses/${resourceId}`;
    const analysisHeaders = {
      'x-apikey': process.env.VIRUSTOTAL_API_KEY,
      accept: 'application/json',
    };
  
    const checkFile = setInterval(async () => {
      try {
        const analysisResponse = await axios.get(analysisUrl,{
          headers: analysisHeaders,
        });
        
  
        if (analysisResponse.data.data.attributes.status === 'completed') {
          clearInterval(checkFile);
  
          const stats = analysisResponse.data.data.attributes.stats;
          const harmfulEngines = stats.harmful || 0;
          const harmlessEngines = stats.harmless || 0;
          const undetectedEngines = stats.undetected || 0;
          const totalEngines = harmfulEngines + harmlessEngines + undetectedEngines;
  
          let result = 'No threats detected!';
          if (harmfulEngines > 0) {
             result = `⚠️ WARNING! This file is malicious according to VirusTotal.\n\n` +
                     `Detected by ${analysisResponse.data.data.attributes.stats.malicious} out of ${analysisResponse.data.data.attributes.stats.undetected} engines.\n\n` +
                    `Malicious engines: ${maliciousEngines.join(', ')}`;
                    ctx.reply(result);
          } else if (undetectedEngines > 0) {
            result = `✅ This file is safe according to VirusTotal.\n\n` +
                     `Detected by ${analysisResponse.data.data.attributes.stats.harmless} out of ${analysisResponse.data.data.attributes.stats.undetected} engines.`;
                     ctx.reply(result);
          }
          
          
        }
      } catch (error) {
        console.error(error);
      }
    }, 5000);
  
    ctx.reply(
      `Your File is Beign scanned.....🕵️‍♂️🕤`
    );
  });


// Start the bot
bot.startPolling();
