let uploadedFile = req.files.file;

fs.writeFile('/uploads/' + uploadedFile.name, uploadedFile.data, (err) => {
    if (err) throw err;
    console.log("File saved!");
});
