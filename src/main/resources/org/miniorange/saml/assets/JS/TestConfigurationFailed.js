const copyButton = document.querySelector("#copy-button");

if (copyButton) {
    copyButton.onclick = function() {
        const errorMsg = document.querySelector("#errormsg");
        if (errorMsg) {
            errorMsg.select();
            document.execCommand('copy');
        }
    };
}

 const doneButton = document.getElementById("doneButton");

 doneButton.addEventListener("click", function() {

    const userConfirmed = confirm("Are you sure you want to close the window?");
    if (userConfirmed) {
        window.close();
    }
 });