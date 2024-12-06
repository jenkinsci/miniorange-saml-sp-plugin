document.addEventListener('DOMContentLoaded', function () {
    const closeBtn = document.getElementById('close-btn');
    const modalBtn = document.querySelector('.free-trial-btn');
    closeBtn.addEventListener('click', handleCloseBtn);
    modalBtn.addEventListener('click', handleModal);
});
