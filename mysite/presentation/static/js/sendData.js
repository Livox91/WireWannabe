function sendDataToBackend(payload) {

    const backendURL = "http://127.0.0.1:8000/receive/";


    fetch(backendURL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCSRFToken()
        },
        body: JSON.stringify(payload)
    })
        .then(response => response.json())
        .then(data => {
            console.log("Response from backend:", data);

        })
        .catch(error => {
            console.error("Error sending data to backend:", error);
            // alert("Failed to send data to the backend.");
        });
}


function getCSRFToken() {
    const name = "csrftoken";
    const cookies = document.cookie.split(";");
    for (let cookie of cookies) {
        const [key, value] = cookie.trim().split("=");
        if (key === name) {
            return value;
        }
    }
    return "";
}