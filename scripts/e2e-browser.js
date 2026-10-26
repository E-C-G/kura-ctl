// Essai de bout en bout dans Chromium (Playwright) : voir « Développement » dans le README.
const { chromium } = require('playwright');
const fs = require('fs');
const f = process.argv[2];
(async () => {
  for (let i = 0; i < 300 && !fs.existsSync(f); i++) await new Promise(r => setTimeout(r, 200));
  const base = fs.readFileSync(f, 'utf8');
  console.log('adresse', base);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', e => errors.push(String(e)));
  try {
    await page.goto(base);
    console.log('1.', page.url());
    await page.fill('input[name=password]', 'un mot de passe solide');
    await page.fill('input[name=password2]', 'un mot de passe solide');
    await page.fill('input[name=access_key_id]', 'AKIDADMIN');
    await page.fill('input[name=secret_access_key]', 'SECRET');
    await Promise.all([page.waitForNavigation(), page.click('form button')]);
    console.log('2. après setup', page.url(), (await page.textContent('body')).includes('Console configurée'));
    await page.fill('input[name=poste]', 'SRV01');
    await Promise.all([page.waitForNavigation(), page.click('table.import button')]);
    console.log('3. après import', page.url(), (await page.textContent('body')).includes('Bucket importé'));
    await page.waitForTimeout(1500);
    await page.goto(base);
    console.log('4. vue d\'ensemble', page.url(), await page.locator('h1').first().textContent());
    await page.screenshot({ path: f + '.png', fullPage: true });
    await Promise.all([page.waitForNavigation(), page.click('form[action="/lock"] button')]);
    console.log('5. après verrouillage', page.url());
    await page.fill('input[name=password]', 'un mot de passe solide');
    await Promise.all([page.waitForNavigation(), page.click('form button')]);
    console.log('6. après déverrouillage', page.url());
    await page.goto(base + 'settings');
    await page.fill('input[name=price]', '7,50');
    await Promise.all([page.waitForNavigation(), page.click('form[action="/settings"] button')]);
    console.log('7. réglages', (await page.textContent('body')).includes('Réglages enregistrés'));
  } catch (e) {
    console.log('ÉCHEC', e.message, page.url());
    console.log((await page.textContent('body')).slice(0, 400));
  }
  console.log('erreurs console :', errors);
  await browser.close();
  fs.writeFileSync(f + '.fin', '');
})();
