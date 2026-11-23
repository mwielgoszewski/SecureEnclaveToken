const tour = {
  identity: { image: 'assets/identity.png', alt: 'Secure Enclave Token showing a loaded client certificate and identity controls', caption: 'Keep the certificate with its key. Export it, replace it, or remove the identity while keeping the private key.' },
  create: { image: 'assets/create-key.png', alt: 'New key dialog with a name, availability policy, and authentication policy', caption: 'Give each key a name and choose its availability and authentication policy. These policies are fixed at creation.' },
  extensions: { image: 'assets/certificate-extensions.png', alt: 'Certificate form with standard extended key usage checkboxes and custom OID controls', caption: 'Choose standard usages with a checkbox, or add custom OIDs and X.509 extensions for the identity you need.' }
};
function activateTab(tab) {
  const list = tab.closest('[role="tablist"]');
  list.querySelectorAll('[role="tab"]').forEach(item => {
    const active = item === tab;
    item.setAttribute('aria-selected', String(active));
    item.tabIndex = active ? 0 : -1;
    if (!tab.dataset.tour) document.getElementById(item.getAttribute('aria-controls')).hidden = !active;
  });
  if (tab.dataset.tour) {
    const item = tour[tab.dataset.tour];
    document.getElementById('tour-image').src = item.image;
    document.getElementById('tour-image').alt = item.alt;
    document.getElementById('tour-caption').textContent = item.caption;
    document.getElementById('tour-panel').setAttribute('aria-labelledby', tab.id);
  }
}
document.querySelectorAll('[role="tablist"]').forEach(list => {
  const tabs = [...list.querySelectorAll('[role="tab"]')];
  tabs.forEach(tab => {
    tab.addEventListener('click', () => activateTab(tab));
    tab.addEventListener('keydown', event => {
      let index = tabs.indexOf(tab);
      if (event.key === 'ArrowRight') index = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') index = (index - 1 + tabs.length) % tabs.length;
      else if (event.key === 'Home') index = 0;
      else if (event.key === 'End') index = tabs.length - 1;
      else return;
      event.preventDefault();
      activateTab(tabs[index]);
      tabs[index].focus();
    });
  });
});
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const code = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = 'Copied';
      document.getElementById('copy-status').textContent = 'Code copied to clipboard.';
    } catch {
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges(); selection.addRange(range);
      button.textContent = 'Selected';
      document.getElementById('copy-status').textContent = 'Copy unavailable. Code selected; use your browser’s Copy command.';
    }
    clearTimeout(button.resetTimer);
    button.resetTimer = setTimeout(() => { button.textContent = 'Copy'; }, 2200);
  });
});
const dialog = document.getElementById('image-dialog');
document.querySelector('.screenshot-button').addEventListener('click', () => {
  const source = document.getElementById('tour-image');
  const image = document.getElementById('dialog-image');
  image.src = source.src; image.alt = source.alt;
  dialog.showModal();
});
dialog.querySelector('.dialog-close').addEventListener('click', () => dialog.close());
dialog.addEventListener('click', event => {
  if (event.target !== dialog) return;
  const bounds = dialog.getBoundingClientRect();
  if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
});
