
function getParameter(parameterName){
    parameter = new URLSearchParams(window.location.search).get(parameterName);
    if (parameter === null){
        return undefined;
    }else{
        return parameter;
    }
}

dest = getParameter("dest");
level = getParameter("level");
const TRUSTED_SCHEMES = {
    "default": ["http:","https:"],
    "trailing_slash": ["http://","https://"]
};
const TRUSTED_DOMAINS = ["securityflaws.net", "google.com"];
const TRUSTED_URLS = ["http://securityflaws.net", "https://google.com"];

if (level === undefined){

        level = 0;
}else{

    level = parseInt(level);
}

if (dest !== undefined){
    if (level === 0){

        window.location = dest;

    }else if (level === 1){

        window.location.replace(dest);

    } else if (level === 2){

        window.location.assign(dest);

    } else if (level === 3){

        window.location.href = dest;

    } else if (level === 4){
        // XSS => javascript:alert(8585)//http:

        redirection_flag = false;
        TRUSTED_SCHEMES["trailing_slash"].forEach(function callback(scheme, index) {

            if (dest.includes(scheme)){
                location = dest;
                redirection_flag = true;
            }else{
                if (redirection_flag === false && index === TRUSTED_SCHEMES["trailing_slash"].length - 1){
                    // Don't process data: scheme is untrsuted
                    alert("Warning: Untrusted scheme in redirection")
                }
            }
        });
    } else if (level === 5){
        // It is Safe against XSS, Open Redirect still exist => https://evil.com

        error = false;
        try {
            dest_scheme = new URL(dest).protocol;
        } catch (e){ 
            if (e instanceof TypeError){
                // Don't process data: URL is malformed
                error = true;
            }
        }
        if (error === false && TRUSTED_SCHEMES["default"].includes(dest_scheme)){
            location = dest;
        }else{
            alert("Warning: Untrusted scheme in redirection");
        }

    } else if (level === 6){
        // It is Safe against XSS, Open Redirect still exist

        redirection_flag = false;
        TRUSTED_SCHEMES["trailing_slash"].forEach(function callback(scheme, index) {

            if (dest.startsWith(scheme)){
                redirection_flag = true;
                location = dest;
            }else{
                if (redirection_flag === false && index === TRUSTED_SCHEMES["default"].length - 1){
                    // don't process data: scheme is untrsuted
                    alert("Warning: Untrusted scheme in redirection")
                }
            }
        })
    } else if (level === 7){
        // It is Safe against XSS, Open Redirect still exist => http://securityflaws.net@evil.com

        redirection_flag = false;
        TRUSTED_URLS.forEach(function callback(url, index) {
            if (dest.startsWith(url)){
                redirection_flag = true;
                location = dest;
            }else{
                if (redirection_flag === false && index === TRUSTED_URLS.length - 1){
                    // don't process data: scheme is untrsuted
                    alert("Warning: Untrusted url in redirection")
                }
            }
        })
    
    } else if (level === 8){
        // It is Safe

        error = false;
        // Scheme validation & Domain validation
        try {
            dest_scheme = new URL(dest).protocol;
            dest_domain = new URL(dest).host;
            if (TRUSTED_SCHEMES["default"].includes(dest_scheme) === false || TRUSTED_DOMAINS.includes(dest_domain) === false){
                error = true;
            }
        } catch (e){
            if (e instanceof TypeError){
                // Don't process data: URL is untrsuted
                error = true;
            }
        }

        if (error === true){
            alert("Warning: Untrusted url in redirection")
        }else{
            location = dest;
        }

    } else if (level === 9){

        $(location).attr("href",dest);
    
    } else{

    }
}
