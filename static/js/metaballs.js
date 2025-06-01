(() => {
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const isMobile = window.matchMedia('(max-width: 768px)').matches;
  
  if (prefersReducedMotion.matches || isMobile) return;

  const canvas = document.getElementById('metaballs');
  const ctx = canvas.getContext('2d');
  
  // Add padding constant
  const EDGE_PADDING = 200; // Pixels of padding around viewport
  
  let width = canvas.width = window.innerWidth + (EDGE_PADDING * 2);
  let height = canvas.height = window.innerHeight + (EDGE_PADDING * 2);
  
  const metaballs = [];
  
  class Metaball {
    constructor() {
      this.x = Math.random() * (width - EDGE_PADDING * 2) + EDGE_PADDING;
      this.y = Math.random() * (height - EDGE_PADDING * 2) + EDGE_PADDING;
      this.vx = (Math.random() - 0.5) * 0.8;
      this.vy = (Math.random() - 0.5) * 0.8;
      this.r = Math.random() * 600 + 450; // Increased from (150 + 100) to (200 + 150)
    }
    
    update(scrollY) {
      this.x += this.vx;
      this.y += this.vy + (scrollY * 0.02);
      
      // Adjusted wrap boundaries with padding
      if (this.x < -this.r - EDGE_PADDING) this.x = width + this.r - EDGE_PADDING;
      if (this.x > width + this.r - EDGE_PADDING) this.x = -this.r - EDGE_PADDING;
      if (this.y < -this.r - EDGE_PADDING) this.y = height + this.r - EDGE_PADDING;
      if (this.y > height + this.r - EDGE_PADDING) this.y = -this.r - EDGE_PADDING;
    }
  }
  
  for (let i = 0; i < 15; i++) { // Increased from 4 to 6 balls
    metaballs.push(new Metaball());
  }
  
  let lastScrollY = 0;
  let scrollVelocity = 0;
  
  window.addEventListener('scroll', () => {
    scrollVelocity = (window.scrollY - lastScrollY) * 0.1;
    lastScrollY = window.scrollY;
  }, { passive: true });
  
  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth + (EDGE_PADDING * 2);
    height = canvas.height = window.innerHeight + (EDGE_PADDING * 2);
  }, { passive: true });
  
  function draw() {
    ctx.clearRect(0, 0, width, height);
    
    // Pure white background required for contrast filter
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);
    
    // Pure black metaballs required for contrast filter
    ctx.fillStyle = '#000000';  // This makes the balls black
    metaballs.forEach(ball => {
      ball.update(scrollVelocity);
      ctx.beginPath();
      ctx.arc(ball.x, ball.y, ball.r, 0, Math.PI * 2);
      ctx.fill();
    });
    
    requestAnimationFrame(draw);
  }
  
  // Start animation when page is visible
  if (document.visibilityState === 'visible') {
    draw();
  }
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      draw();
    }
  });
})();
