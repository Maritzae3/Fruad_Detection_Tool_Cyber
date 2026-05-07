// Will run when homepage loads
document.addEventListener("DOMContentLoaded", () => {
    setupHomeAnimations();
  });
  // the document.addEventListener() is what the js file looks for to then trigger the functions. for example we use
  // "DOMContentLoaded", this means that when the page elements load then it will be triggered to start the animations

  // this function will control the animations for the homepage
  function setupHomeAnimations() {
    if (typeof gsap === "undefined" || typeof ScrollTrigger === "undefined") {
      return;
    }
  
    gsap.registerPlugin(ScrollTrigger);
  
    // animating the hero section when the page loads
    gsap.from(".home-hero-content", {
        opacity: 0,
        y: 40,
        duration: 1,
        ease: "power3.out"   // power3.out has more of a dramatic deceleration
      });
  
    // animating the hero card sliding in
    gsap.from(".home-hero-card", {
      opacity: 0,
      x: 40,
      duration: 0.9,
      delay: 0.2,
      ease: "power2.out" // power2.out is a GSAP function to create smooth natural 'decalration' at end of animation
      // it starts off a little fast and then eases down into place
    });
  
    // animating the sections when scrolling down
    gsap.utils.toArray(".reveal").forEach((element) => {
      gsap.from(element, {
        opacity: 0,
        y: 55,
        duration: 0.8,
        ease: "power2.out",
        scrollTrigger: {
          trigger: element,
          start: "top 85%",
          toggleActions: "play none none reverse"
        }
      });
    });
}