let userReferrer = document.referrer;
let sanitizedReferrer = DOMPurify.sanitize(userReferrer);
document.getElementById("output").innerHTML = sanitizedReferrer;
