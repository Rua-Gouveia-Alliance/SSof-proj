userReferrer = document.referrer;
sanitizedReferrer = DOMPurify.sanitize(userReferrer);
document.getElementById("output").innerHTML = sanitizedReferrer;
