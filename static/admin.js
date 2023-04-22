
function getParameter(parameterName){
    parameter = new URLSearchParams(window.location.search).get(parameterName);
    if (parameter === null){
        return undefined;
    }else{
        return parameter;
    }
}

function getCookie(cname) {
    let name = cname + "=";
    let decodedCookie = decodeURIComponent(document.cookie);
    let ca = decodedCookie.split(';');
    for (let i = 0; i <ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

returnUrl = getParameter("returnUrl");

if (returnUrl === undefined){
    // Nothing | Parameter not specified
} else if (returnUrl.trim() === ""){
    // Drop parameters if returnUrl is empty
    urlObject = new URL(window.location.href);
    window.location = `${urlObject.origin}${urlObject.pathname}`;
} else{
    // Redirect
    window.location = returnUrl;
}
