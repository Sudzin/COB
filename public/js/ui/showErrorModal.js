export function showErrorModal(msg) {
  document.getElementById('errModalText').textContent = msg;
  document.getElementById('errModal').style.display = 'grid';
}
