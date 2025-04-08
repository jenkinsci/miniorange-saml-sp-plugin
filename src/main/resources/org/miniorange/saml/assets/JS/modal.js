var modal = document.getElementById("modal-dialog");
var uploadJson = document.getElementById("upload-saml-json-config");


const openUploadConfigModal = document.getElementById('openUploadConfigModal');
const modalCloseBtn = document.getElementById('close-btn');
const modalOpenButton = document.getElementById('modal-open-button');

const GetYourPremiumTrialBtn = document.getElementById('GetYourPremiumTrialBtn');
const GetYourPremiumTrialBtn2 = document.getElementById('GetYourPremiumTrialBtn2');
const confirmButton = document.getElementById('confirm-button');
const cancelButton = document.getElementById('cancel-button');
const closeButton = document.querySelector('.close-btn');

function handleModal() {
    modal.style.display = "block";
}

function handleCloseBtn() {
    modal.style.display = "none";
}
function uploadConfig() {
    uploadJson.style.display = "block";
}


function submitConfirmationPopupForm() {
    return new Promise((resolve, reject) => {
        const name = document.getElementById('name').value;
        const orgName = document.getElementById('orgName').value;
        const email = document.getElementById('email').value;

        const isValidName = /^[a-zA-Z ]{2,30}$/.test(name);
        const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

        if (!isValidName) {
            alert('Please enter a valid name (2-30 characters, letters and spaces only).');
            reject('Invalid name');
            return;
        }
        if (!isValidEmail) {
            alert('Please enter a valid email address.');
            reject('Invalid email');
            return;
        }
        document.forms['confirmationForm'].submit();
        setTimeout(() => {
            resolve();
        }, 3000);
    });
}



function submitInstallForm() {
    document.getElementById('installPluginForm').submit();
}
function closeConfirmationPopup() {
    document.getElementById('overlay').style.display = 'none';
    document.getElementById('confirmationPopup').style.display = 'none';
}
function showConfirmationPopup() {
    document.getElementById('close-btn').click();
    document.getElementById('overlay').style.display = 'block';
    document.getElementById('confirmationPopup').style.display = 'block';
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

if(GetYourPremiumTrialBtn){
    GetYourPremiumTrialBtn.addEventListener('click',function (){
        showConfirmationPopup();
    });
}

if(GetYourPremiumTrialBtn2){
    GetYourPremiumTrialBtn2.addEventListener('click',function (){
        showConfirmationPopup();
    });
}

if (confirmButton) {
    confirmButton.addEventListener('click', async function () {
        console.log("calling submitConfirmationPopupForm function.. ");
        try {
            await submitConfirmationPopupForm();
            submitInstallForm();
        } catch (error) {
            console.log("Error occurred:", error);
        }
    });
}

if (closeButton){
    closeButton.addEventListener('click',()=>{
        closeConfirmationPopup();
    })
}

if (cancelButton){
    cancelButton.addEventListener('click',function (){
        closeConfirmationPopup();
    })
}