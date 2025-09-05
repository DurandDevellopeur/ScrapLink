const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

// Configuration des User-Agents
const USER_AGENTS = {
  'desktop': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
  'mobile': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
  'alyze': 'Alyze-Bot/1.0 (+https://alyze.info/crawler)'
};

// Configuration des localisations
const LOCATIONS = {
  'france': { 'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8' },
  'us': { 'Accept-Language': 'en-US,en;q=0.9' },
  'spain': { 'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8' }
};

// Fonction pour créer les headers HTTP
function createHeaders(userAgent = 'desktop', location = 'france') {
  return {
    'User-Agent': USER_AGENTS[userAgent] || USER_AGENTS['desktop'],
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    ...LOCATIONS[location]
  };
}

// Fonction pour normaliser les URLs
function normalizeUrl(url, baseUrl) {
  try {
    return new URL(url, baseUrl).href;
  } catch (e) {
    return null;
  }
}

// Fonction pour vérifier si une URL est interne
function isInternalUrl(url, domain) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain);
  } catch (e) {
    return false;
  }
}

// Fonction d'analyse de sécurité
function analyzeSecurityIssues(url, html, headers) {
  const $ = cheerio.load(html);
  const issues = [];

  // Vérification HTTPS
  if (!url.startsWith('https://')) {
    issues.push({
      type: 'HTTP_INSECURE',
      niveau: 'critique',
      détails: 'Le site utilise HTTP non sécurisé',
      recommandation: 'Migrer vers HTTPS avec un certificat SSL/TLS valide'
    });
  }

  // Vérification des headers de sécurité
  const securityHeaders = {
    'x-frame-options': 'Header X-Frame-Options manquant (protection contre le clickjacking)',
    'x-content-type-options': 'Header X-Content-Type-Options manquant (protection MIME sniffing)',
    'x-xss-protection': 'Header X-XSS-Protection manquant (protection XSS basique)',
    'strict-transport-security': 'Header HSTS manquant (sécurité transport)',
    'content-security-policy': 'Header CSP manquant (politique de sécurité du contenu)'
  };

  Object.keys(securityHeaders).forEach(header => {
    if (!headers[header] && !headers[header.toUpperCase()]) {
      issues.push({
        type: 'MISSING_SECURITY_HEADER',
        niveau: 'moyen',
        détails: securityHeaders[header],
        recommandation: `Ajouter le header ${header.toUpperCase()}`
      });
    }
  });

  // Vérification des formulaires
  $('form').each((i, form) => {
    const $form = $(form);
    const method = $form.attr('method') || 'GET';
    const action = $form.attr('action') || '';

    // Vérification CSRF
    const hasCSRFToken = $form.find('input[name*="csrf"], input[name*="token"], input[name="_token"]').length > 0;
    if (method.toLowerCase() === 'post' && !hasCSRFToken) {
      issues.push({
        type: 'CSRF_MISSING',
        niveau: 'critique',
        détails: `Formulaire POST sans protection CSRF: ${action}`,
        recommandation: 'Ajouter un token CSRF au formulaire'
      });
    }

    // Vérification champs password
    $form.find('input[type="password"]').each((j, input) => {
      const $input = $(input);
      if (!$input.attr('autocomplete') || $input.attr('autocomplete') !== 'off') {
        issues.push({
          type: 'PASSWORD_AUTOCOMPLETE',
          niveau: 'faible',
          détails: 'Champ mot de passe sans autocomplete="off"',
          recommandation: 'Désactiver l\'autocomplétion pour les mots de passe'
        });
      }
    });
  });

  // Vérification scripts inline
  $('script').each((i, script) => {
    const $script = $(script);
    if ($script.html() && $script.html().trim()) {
      const content = $script.html();
      if (content.includes('eval(') || content.includes('innerHTML') || content.includes('document.write')) {
        issues.push({
          type: 'DANGEROUS_SCRIPT',
          niveau: 'moyen',
          détails: 'Script inline avec fonctions potentiellement dangereuses',
          recommandation: 'Éviter eval(), innerHTML et document.write'
        });
      }
    }
  });

  // Vérification liens suspects
  $('a[href]').each((i, link) => {
    const href = $(link).attr('href');
    if (href && href.includes('?')) {
      const params = new URLSearchParams(href.split('?')[1]);
      for (const [key, value] of params) {
        if (value && (value.includes('<script') || value.includes('javascript:') || value.includes('SELECT') || value.includes('UNION'))) {
          issues.push({
            type: 'SUSPICIOUS_PARAMETER',
            niveau: 'critique',
            détails: `Paramètre suspect dans le lien: ${key}=${value}`,
            recommandation: 'Valider et échapper tous les paramètres GET'
          });
        }
      }
    }
  });

  return issues;
}

// Route d'analyse de sécurité
app.post('/api/scan', async (req, res) => {
  try {
    const { 
      url, 
      depth = 1, 
      includeAssets = false,
      userAgent = 'desktop',
      location = 'france',
      followRedirects = true,
      language = 'auto'
    } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL requise' });
    }

    const visitedUrls = new Set();
    const pages = [];
    const urlsToVisit = [url];
    const baseUrl = new URL(url);
    const domain = baseUrl.hostname;

    const axiosConfig = {
      headers: createHeaders(userAgent, location),
      timeout: 10000,
      maxRedirects: followRedirects ? 5 : 0,
      validateStatus: () => true
    };

    while (urlsToVisit.length > 0 && pages.length < depth) {
      const currentUrl = urlsToVisit.shift();
      
      if (visitedUrls.has(currentUrl)) continue;
      visitedUrls.add(currentUrl);

      try {
        const response = await axios.get(currentUrl, axiosConfig);
        const html = response.data;
        const headers = response.headers;

        // Analyse de sécurité
        const failles = analyzeSecurityIssues(currentUrl, html, headers);

        pages.push({
          url: currentUrl,
          status: response.status,
          failles: failles
        });

        // Si on n'a pas atteint la profondeur max, chercher d'autres liens
        if (pages.length < depth) {
          const $ = cheerio.load(html);
          $('a[href]').each((i, link) => {
            const href = $(link).attr('href');
            const fullUrl = normalizeUrl(href, currentUrl);
            
            if (fullUrl && isInternalUrl(fullUrl, domain) && !visitedUrls.has(fullUrl) && !urlsToVisit.includes(fullUrl)) {
              urlsToVisit.push(fullUrl);
            }
          });
        }
      } catch (error) {
        pages.push({
          url: currentUrl,
          status: 'error',
          failles: [{
            type: 'CONNECTION_ERROR',
            niveau: 'critique',
            détails: `Erreur de connexion: ${error.message}`,
            recommandation: 'Vérifier la disponibilité du site'
          }]
        });
      }
    }

    // Calcul du résumé
    let faillesCritiques = 0;
    let faillesMoyennes = 0;
    let faillesFaibles = 0;

    pages.forEach(page => {
      if (page.failles) {
        page.failles.forEach(faille => {
          switch (faille.niveau) {
            case 'critique': faillesCritiques++; break;
            case 'moyen': faillesMoyennes++; break;
            case 'faible': faillesFaibles++; break;
          }
        });
      }
    });

    res.json({
      pages: pages,
      résumé: {
        totalPages: pages.length,
        faillesCritiques: faillesCritiques,
        faillesMoyennes: faillesMoyennes,
        faillesFaibles: faillesFaibles
      }
    });

  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur: ' + error.message });
  }
});

// Route de scraping avancé
app.post('/api/scrape', async (req, res) => {
  try {
    const { 
      url, 
      pages: maxPages = 1, 
      includeAssets = false,
      userAgent = 'desktop',
      location = 'france',
      followRedirects = true,
      language = 'auto'
    } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL requise' });
    }

    const visitedUrls = new Set();
    const scrapedPages = [];
    const urlsToVisit = [url];
    const baseUrl = new URL(url);
    const domain = baseUrl.hostname;

    const axiosConfig = {
      headers: createHeaders(userAgent, location),
      timeout: 15000,
      maxRedirects: followRedirects ? 5 : 0,
      validateStatus: () => true
    };

    while (urlsToVisit.length > 0 && scrapedPages.length < maxPages) {
      const currentUrl = urlsToVisit.shift();
      
      if (visitedUrls.has(currentUrl)) continue;
      visitedUrls.add(currentUrl);

      try {
        const response = await axios.get(currentUrl, axiosConfig);
        const html = response.data;
        const $ = cheerio.load(html);

        // Extraction des données
        const pageData = {
          url: currentUrl,
          status: response.status,
          title: $('title').text().trim() || 'Sans titre',
          description: $('meta[name="description"]').attr('content') || '',
          h1: [],
          liens: [],
          images: [],
          css: [],
          scripts: [],
          formulaires: []
        };

        // Extraction H1
        $('h1').each((i, h1) => {
          pageData.h1.push($(h1).text().trim());
        });

        // Extraction liens
        $('a[href]').each((i, link) => {
          const $link = $(link);
          const href = $link.attr('href');
          const text = $link.text().trim();
          const fullUrl = normalizeUrl(href, currentUrl);
          
          if (fullUrl) {
            pageData.liens.push({
              url: fullUrl,
              text: text,
              internal: isInternalUrl(fullUrl, domain)
            });

            // Ajouter à la liste des URLs à visiter si interne
            if (scrapedPages.length < maxPages && isInternalUrl(fullUrl, domain) && !visitedUrls.has(fullUrl) && !urlsToVisit.includes(fullUrl)) {
              urlsToVisit.push(fullUrl);
            }
          }
        });

        // Extraction images
        $('img[src]').each((i, img) => {
          const $img = $(img);
          const src = $img.attr('src');
          const alt = $img.attr('alt') || '';
          const fullUrl = normalizeUrl(src, currentUrl);
          
          if (fullUrl) {
            pageData.images.push({
              src: fullUrl,
              alt: alt
            });
          }
        });

        if (includeAssets) {
          // Extraction CSS
          $('link[rel="stylesheet"], style').each((i, css) => {
            const $css = $(css);
            if ($css.is('link')) {
              const href = $css.attr('href');
              const fullUrl = normalizeUrl(href, currentUrl);
              if (fullUrl) {
                pageData.css.push({
                  type: 'external',
                  url: fullUrl
                });
              }
            } else {
              pageData.css.push({
                type: 'inline',
                content: $css.html()
              });
            }
          });

          // Extraction JavaScript
          $('script').each((i, script) => {
            const $script = $(script);
            const src = $script.attr('src');
            
            if (src) {
              const fullUrl = normalizeUrl(src, currentUrl);
              if (fullUrl) {
                pageData.scripts.push({
                  type: 'external',
                  url: fullUrl
                });
              }
            } else if ($script.html()) {
              pageData.scripts.push({
                type: 'inline',
                content: $script.html().substring(0, 200) + '...' // Limiter la taille
              });
            }
          });
        }

        // Extraction formulaires
        $('form').each((i, form) => {
          const $form = $(form);
          const formData = {
            method: $form.attr('method') || 'GET',
            action: $form.attr('action') || currentUrl,
            inputs: []
          };

          $form.find('input, select, textarea').each((j, input) => {
            const $input = $(input);
            formData.inputs.push({
              type: $input.attr('type') || $input[0].tagName.toLowerCase(),
              name: $input.attr('name') || '',
              placeholder: $input.attr('placeholder') || '',
              required: $input.attr('required') ? true : false
            });
          });

          pageData.formulaires.push(formData);
        });

        scrapedPages.push(pageData);

      } catch (error) {
        scrapedPages.push({
          url: currentUrl,
          status: 'error',
          error: error.message,
          title: 'Erreur de chargement',
          description: '',
          h1: [],
          liens: [],
          images: [],
          css: [],
          scripts: [],
          formulaires: []
        });
      }
    }

    res.json({
      pages: scrapedPages,
      totalPages: scrapedPages.length,
      requestedPages: maxPages
    });

  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur: ' + error.message });
  }
});

// Route de base
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Cyber Analyzer Pro démarré sur le port ${PORT}`);
  console.log(`🌐 Interface accessible sur http://localhost:${PORT}`);
});
