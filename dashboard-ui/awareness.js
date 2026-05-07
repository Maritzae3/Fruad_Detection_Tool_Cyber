// will run when the page loads, 'listens' for when the content is loaded and then will trigger the animations
document.addEventListener("DOMContentLoaded", () => {
    setupFAQ();
    setupScrollAnimations();  // calling to the functions
  });

  // this function will be listening for the faq triggers and selects all the elements that have certain class names
  function setupFAQ() {
    const faqItems = document.querySelectorAll(".faq-item");  // this line is selecting the elements that have "faq-item" as their class name=
  
    faqItems.forEach((item) => {
      const questionButton = item.querySelector(".faq-question");
  
      questionButton.addEventListener("click", () => {  // adding a trigger for when the user clicks on an faq-question item
        const isOpen = item.classList.contains("active");  // labeling that specific question active so it stays open
  
        faqItems.forEach((faq) => faq.classList.remove("active"));  // making all other questions 'inactive' so they close and the main question selected is open
  
        if (!isOpen) {
          item.classList.add("active");  // this opens a clicked questions if it wasnt open already
        }
      });
    });
  }
  
  // handles the scrolling function using GSAP
  function setupScrollAnimations() {
    if (typeof gsap === "undefined" || typeof ScrollTrigger === "undefined") {
      return;
    }
  
    gsap.registerPlugin(ScrollTrigger);
  
    // animate the elements on the screen as the user scrolls
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
  
    gsap.from(".hero-content", {
      opacity: 0,
      y: 35,
      duration: 0.9,
      ease: "power2.out"
    });
  
    gsap.from(".hero-card", {
      opacity: 0,
      x: 40,
      duration: 0.9,
      delay: 0.2,
      ease: "power2.out"
    });
  }