
        // Global Drag and Drop protection
        window.addEventListener('dragover', function(e) {
            e.preventDefault();
        }, false);
        window.addEventListener('drop', function(e) {
            e.preventDefault();
        }, false);
    