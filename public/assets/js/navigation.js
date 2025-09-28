class NavigationManager {
  constructor() {
    this.navItems = document.querySelectorAll(".navigation li");
    this.initNavigation();
    this.initActiveLinks();
  }

  initNavigation() {
    const toggle = document.querySelector('.toggle');
    if (!toggle) return;

    const navigation = document.querySelector('.navigation');
    const main = document.querySelector('.main');

    toggle.addEventListener('click', () => {
      navigation.classList.toggle('active');
      main.classList.toggle('active');
    });
  }

  initActiveLinks() {
    this.navItems.forEach(item => {
      item.addEventListener('mouseover', () => {
        this.navItems.forEach(i => i.classList.remove('hovered'));
        item.classList.add('hovered');
      });
    });
  }
}

// Initialize when DOM is loaded
if (document.querySelector('.navigation')) {
  document.addEventListener('DOMContentLoaded', () => {
    new NavigationManager();
  });
}