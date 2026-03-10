// Greyhat4Hire — Shared Footer Component
// Edit this ONE file to update the footer across the entire site.
(function () {
  const html = `
<footer style="position:relative;z-index:2;border-top:1px solid rgba(255,20,147,.1);background:rgba(0,0,0,.5);">
  <div style="max-width:72rem;margin:0 auto;padding:3.5rem 1.5rem 2.5rem;">

    <!-- ── Link columns ── -->
    <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:2rem 1.5rem;margin-bottom:2.5rem;" class="gh4h-footer-grid">
      <div>
        <div style="font-family:'Orbitron',monospace;font-size:.6rem;letter-spacing:.18em;color:rgba(255,20,147,.45);margin-bottom:.75rem;">PAGES</div>
        <div style="display:flex;flex-direction:column;gap:.45rem;">
          <a href="index.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Home</a>
          <a href="about.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">About</a>
          <a href="services.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Services</a>
          <a href="our-process.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Our Process</a>
          <a href="pricing.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Pricing</a>
          <a href="blog.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Blog</a>
          <a href="contact.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Contact</a>
        </div>
      </div>
      <div>
        <div style="font-family:'Orbitron',monospace;font-size:.6rem;letter-spacing:.18em;color:rgba(255,20,147,.45);margin-bottom:.75rem;">FREE TOOLS</div>
        <div style="display:flex;flex-direction:column;gap:.45rem;">
          <a href="risk-assessment.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Risk Self-Assessment</a>
          <a href="hackers-dossier.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Hacker's Dossier</a>
          <a href="breach-cost-clock.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Breach Cost Clock</a>
          <a href="vuln-lookup.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Vulnerability Intelligence</a>
          <a href="reverse-image-search.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Reverse Image Search</a>
          <a href="downloads.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">The Arsenal</a>
          <a href="cyber-awareness.html" style="color:#9ca3af;font-size:.85rem;text-decoration:none;transition:color .2s;">Cyber Awareness</a>
        </div>
      </div>
    </div>

    <!-- ── Contact strip ── -->
    <div style="display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:2rem;">
      <a href="mailto:david@greyhat4hire.com" style="display:inline-flex;align-items:center;gap:6px;color:#9ca3af;font-size:.8rem;text-decoration:none;background:rgba(255,20,147,.04);border:1px solid rgba(255,20,147,.12);border-radius:8px;padding:8px 14px;transition:border-color .2s;">
        <i class="fas fa-envelope" style="color:#ff1493;font-size:.7rem;"></i>david@greyhat4hire.com
      </a>
      <a href="tel:+27846353581" style="display:inline-flex;align-items:center;gap:6px;color:#9ca3af;font-size:.8rem;text-decoration:none;background:rgba(255,20,147,.04);border:1px solid rgba(255,20,147,.12);border-radius:8px;padding:8px 14px;transition:border-color .2s;">
        <i class="fas fa-phone" style="color:#ff1493;font-size:.7rem;"></i>+27 84 635 3581
      </a>
      <a href="https://wa.me/27846353581" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;color:#9ca3af;font-size:.8rem;text-decoration:none;background:rgba(37,211,102,.04);border:1px solid rgba(37,211,102,.15);border-radius:8px;padding:8px 14px;transition:border-color .2s;">
        <i class="fab fa-whatsapp" style="color:#25D366;font-size:.8rem;"></i>WhatsApp
      </a>
      <a href="https://maps.app.goo.gl/qCZ2o4fKLKxp8dYz6" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;color:#9ca3af;font-size:.8rem;text-decoration:none;background:rgba(66,133,244,.04);border:1px solid rgba(66,133,244,.15);border-radius:8px;padding:8px 14px;transition:border-color .2s;">
        <i class="fas fa-map-marker-alt" style="color:#4285F4;font-size:.7rem;"></i>Find us on Google Maps
      </a>
    </div>

    <!-- ── Divider ── -->
    <div style="height:1px;background:linear-gradient(90deg,transparent,rgba(255,20,147,.2),transparent);margin-bottom:1.5rem;"></div>

    <!-- ── NDA + copyright row ── -->
    <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:1rem;">
      <div style="display:flex;align-items:center;gap:8px;">
        <i class="fas fa-shield-alt" style="color:rgba(255,20,147,.5);font-size:.7rem;"></i>
        <span style="font-size:.7rem;color:rgba(255,255,255,.3);font-family:'Rajdhani',sans-serif;">All engagements under strict NDA</span>
      </div>
      <div style="font-size:.7rem;color:rgba(255,255,255,.2);">&copy; 2026 Greyhat4Hire</div>
      <a href="privacy.html" style="font-size:.7rem;color:rgba(255,255,255,.2);text-decoration:none;transition:color .2s;">Privacy Policy</a>
    </div>

  </div>

  <!-- ── Responsive grid override ── -->
  <style>
    .gh4h-footer-grid a:hover{color:#ff69b4 !important;}
    @media(min-width:640px){.gh4h-footer-grid{gap:2.5rem 4rem !important;}}
  </style>
</footer>`;

  document.getElementById('gh4h-footer').outerHTML = html;
})();
