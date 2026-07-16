import puppeteer from 'puppeteer';

(async () => {
  const browser = await puppeteer.launch({ headless: 'new' });
  const page = await browser.newPage();

  page.on('console', msg => {
    if (msg.type() === 'error') {
      console.log('PAGE ERROR:', msg.text());
    } else {
      console.log('PAGE LOG:', msg.text());
    }
  });

  page.on('pageerror', error => {
    console.log('PAGE UNHANDLED EXCEPTION:', error.message);
  });

  page.on('requestfailed', request => {
    console.log('PAGE REQUEST FAILED:', request.url(), request.failure().errorText);
  });

  console.log('Navigating to http://localhost:5174/');
  await page.goto('http://localhost:5174/', { waitUntil: 'networkidle0' });
  console.log('Navigation complete.');
  
  await browser.close();
})();
