var modal = document.getElementById("modal-dialog");
var uploadJson = document.getElementById("upload-saml-json-config");


const openUploadConfigModal = document.getElementById('openUploadConfigModal');
const modalCloseBtn = document.getElementById('close-btn');
const modalOpenButton = document.getElementById('modal-open-button');

function handleModal() {
    modal.style.display = "block";
}

function handleCloseBtn() {
    modal.style.display = "none";
}
function uploadConfig() {
    uploadJson.style.display = "block";
}


window.onclick = function (event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }

    if (event.target == uploadJson) {
        uploadJson.style.display = "none";
    }
}

if (openUploadConfigModal) {
    openUploadConfigModal.addEventListener('click', function(event) {
        uploadConfig();
    });
}

if (modalCloseBtn) {
    modalCloseBtn.addEventListener('click', function (event) {
        handleCloseBtn();
    });
}

if (modalOpenButton) {
    modalOpenButton.addEventListener('click', function(event) {
        handleModal();
    });
}


