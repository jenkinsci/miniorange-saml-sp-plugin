
const checkboxes = document.querySelectorAll('.disable_');
checkboxes.forEach((checkbox) => {
    checkbox.addEventListener('click', function(event) {
        event.preventDefault();
    });
});