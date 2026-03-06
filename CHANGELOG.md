# Greyhat4Hire — Full Site Update

**27 HTML files updated.**

---

## Footer Standardisation (25 pages)

Every page now uses the same premium 4-column footer:

- **Column 1**: Logo, description, WhatsApp link
- **Column 2**: Full page directory (Home, About, Services, Cyber Awareness, Our Process, Pricing, Blog, Contact)
- **Column 3**: All free tools (Risk Assessment, Hacker's Dossier, Breach Cost Clock, Vuln Intel, Reverse Image Search, Downloads)
- **Column 4**: Contact info with icons (Email, Phone, WhatsApp, Book Consultation)
- **Confidentiality badge** + copyright bar on every page

Previously: 15 pages had a compact 2-column footer missing tools, contact details, and the confidentiality badge. All now unified.

---

## Schema Markup (8 new pages)

Every public page now has JSON-LD structured data:

| Page | Schema Type |
|------|-------------|
| breach-cost-clock.html | WebApplication |
| cyber-awareness.html | WebPage |
| downloads.html | WebPage |
| hackers-dossier.html | WebApplication |
| privacy.html | WebPage |
| reverse-image-search.html | WebApplication |
| risk-assessment.html | WebApplication |
| vuln-lookup.html | WebApplication |

All 5 free tools now have `WebApplication` schema with `offers.price: 0` — Google can show these as free tools in search results. Combined with the 18 pages that already had schema, coverage is now 26/27 public pages.

---

## Previously Applied Fixes (included in these files)

- Preconnect hints on all 27 pages
- Dead LinkedIn/Twitter `href="#"` links removed site-wide
- Broken `blog-post.html` link fixed → correct OSINT article
- HIPAA → POPIA/HIPAA on about.html, services.html, index.html
- Meta description added to reverse-image-search.html
- FAQPage schema on index.html (7 questions → Google rich snippets)
- Blog preview section on index.html (3 featured posts)
- Contact page: honeypot spam field, availability indicator, response time guarantee
- Over-long page titles trimmed

---

## How to Deploy

Drop all 27 HTML files into your repo root, replacing the originals. No other files (CSS, images, JS, documents) were changed.
