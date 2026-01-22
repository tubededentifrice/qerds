/**
 * QERDS UI - Main JavaScript
 * Minimal, progressive enhancement only
 */

(function() {
    'use strict';

    // User dropdown toggle
    const userMenuTrigger = document.querySelector('.user-menu-trigger');
    const userDropdown = document.querySelector('.user-dropdown');

    if (userMenuTrigger && userDropdown) {
        userMenuTrigger.addEventListener('click', function(e) {
            e.stopPropagation();
            const isExpanded = this.getAttribute('aria-expanded') === 'true';
            this.setAttribute('aria-expanded', !isExpanded);
            userDropdown.hidden = isExpanded;
        });

        // Close on outside click
        document.addEventListener('click', function() {
            userMenuTrigger.setAttribute('aria-expanded', 'false');
            userDropdown.hidden = true;
        });

        // Close on escape
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                userMenuTrigger.setAttribute('aria-expanded', 'false');
                userDropdown.hidden = true;
            }
        });
    }

    // File input enhancement with validation
    var ALLOWED_EXTENSIONS = ['.pdf', '.doc', '.docx', '.odt'];
    var MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

    /**
     * Format file size in human-readable format.
     * @param {number} bytes - File size in bytes
     * @returns {string} Formatted size string
     */
    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' o';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' Ko';
        return (bytes / (1024 * 1024)).toFixed(2) + ' Mo';
    }

    /**
     * Validate file type and size.
     * @param {File} file - The file to validate
     * @param {HTMLInputElement} input - The file input element
     * @returns {{valid: boolean, error: string|null}} Validation result
     */
    function validateFile(file, input) {
        // Check file extension
        var fileName = file.name.toLowerCase();
        var hasValidExtension = ALLOWED_EXTENSIONS.some(function(ext) {
            return fileName.endsWith(ext);
        });

        if (!hasValidExtension) {
            return {
                valid: false,
                error: 'Type de fichier non autorise. Formats acceptes : PDF, DOC, DOCX, ODT'
            };
        }

        // Check file size (use data attribute if available, otherwise default)
        var maxSize = input.dataset.maxSize ? parseInt(input.dataset.maxSize, 10) : MAX_FILE_SIZE;
        if (file.size > maxSize) {
            return {
                valid: false,
                error: 'Fichier trop volumineux. Taille maximale : ' + formatFileSize(maxSize)
            };
        }

        return { valid: true, error: null };
    }

    /**
     * Show file error message.
     * @param {HTMLElement} container - The form-file container
     * @param {string} message - Error message to display
     */
    function showFileError(container, message) {
        container.classList.add('form-file--error');
        container.classList.remove('form-file--has-file');

        var errorEl = container.parentElement.querySelector('.form-error');
        if (errorEl) {
            errorEl.textContent = message;
            errorEl.hidden = false;
        }

        // Hide selected file display
        var selectedEl = container.querySelector('.form-file-selected');
        if (selectedEl) {
            selectedEl.hidden = true;
        }
    }

    /**
     * Clear file error message.
     * @param {HTMLElement} container - The form-file container
     */
    function clearFileError(container) {
        container.classList.remove('form-file--error');

        var errorEl = container.parentElement.querySelector('.form-error');
        if (errorEl) {
            errorEl.hidden = true;
        }
    }

    /**
     * Display selected file information.
     * @param {HTMLElement} container - The form-file container
     * @param {File} file - The selected file
     */
    function showSelectedFile(container, file) {
        container.classList.add('form-file--has-file');
        clearFileError(container);

        var selectedEl = container.querySelector('.form-file-selected');
        var nameEl = container.querySelector('.form-file-selected-name');
        var sizeEl = container.querySelector('.form-file-selected-size');

        if (selectedEl && nameEl && sizeEl) {
            nameEl.textContent = file.name;
            sizeEl.textContent = formatFileSize(file.size);
            selectedEl.hidden = false;
        }
    }

    /**
     * Clear selected file display.
     * @param {HTMLElement} container - The form-file container
     * @param {HTMLInputElement} input - The file input element
     */
    function clearSelectedFile(container, input) {
        container.classList.remove('form-file--has-file');

        var selectedEl = container.querySelector('.form-file-selected');
        if (selectedEl) {
            selectedEl.hidden = true;
        }

        // Clear the input
        input.value = '';
    }

    // Initialize file inputs
    var fileInputs = document.querySelectorAll('.form-file-input');
    fileInputs.forEach(function(input) {
        var container = input.closest('.form-file');
        var label = container.querySelector('.form-file-label');
        var removeBtn = container.querySelector('.form-file-remove');

        // Handle file selection
        input.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
                var file = this.files[0];
                var validation = validateFile(file, this);

                if (validation.valid) {
                    showSelectedFile(container, file);
                } else {
                    showFileError(container, validation.error);
                    this.value = ''; // Clear invalid file
                }
            }
        });

        // Handle remove button
        if (removeBtn) {
            removeBtn.addEventListener('click', function() {
                clearSelectedFile(container, input);
                clearFileError(container);
            });
        }

        // Drag and drop events
        if (label) {
            label.addEventListener('dragover', function(e) {
                e.preventDefault();
                container.classList.add('form-file--drag-active');
            });

            label.addEventListener('dragleave', function(e) {
                e.preventDefault();
                container.classList.remove('form-file--drag-active');
            });

            label.addEventListener('drop', function(e) {
                e.preventDefault();
                container.classList.remove('form-file--drag-active');

                if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                    // Only accept the first file
                    var file = e.dataTransfer.files[0];
                    var validation = validateFile(file, input);

                    if (validation.valid) {
                        // Create a new DataTransfer to set the files
                        var dt = new DataTransfer();
                        dt.items.add(file);
                        input.files = dt.files;
                        showSelectedFile(container, file);
                    } else {
                        showFileError(container, validation.error);
                    }
                }
            });
        }

        // Also handle drag events on the container for better UX
        container.addEventListener('dragover', function(e) {
            e.preventDefault();
            container.classList.add('form-file--drag-active');
        });

        container.addEventListener('dragleave', function(e) {
            // Only remove class if leaving the container entirely
            if (!container.contains(e.relatedTarget)) {
                container.classList.remove('form-file--drag-active');
            }
        });
    });

    // Radio option styling (only for browsers that don't support :has())
    // Modern browsers use CSS :has() selector, this is a fallback
    if (!CSS.supports('selector(:has(*))')) {
        var radioOptions = document.querySelectorAll('.radio-option');
        radioOptions.forEach(function(option) {
            var input = option.querySelector('input[type="radio"]');
            if (input) {
                function updateStyles() {
                    radioOptions.forEach(function(opt) {
                        var radio = opt.querySelector('input[type="radio"]');
                        if (radio && radio.checked) {
                            opt.style.borderColor = 'var(--color-primary)';
                            opt.style.background = 'rgba(0, 0, 145, 0.04)';
                        } else {
                            opt.style.borderColor = 'transparent';
                            opt.style.background = 'var(--bg-surface-alt)';
                        }
                    });
                }
                input.addEventListener('change', updateStyles);
                // Initial state
                updateStyles();
            }
        });
    }

    // Delivery form submission with progress feedback
    var deliveryForm = document.getElementById('delivery-form');
    if (deliveryForm) {
        var progressOverlay = document.getElementById('form-progress');
        var progressText = document.getElementById('progress-text');
        var btnSend = document.getElementById('btn-send');
        var btnDraft = document.getElementById('btn-draft');

        deliveryForm.addEventListener('submit', function(e) {
            // Check if file validation passes
            var fileInput = deliveryForm.querySelector('.form-file-input');
            if (fileInput && fileInput.files && fileInput.files.length > 0) {
                var validation = validateFile(fileInput.files[0], fileInput);
                if (!validation.valid) {
                    e.preventDefault();
                    var container = fileInput.closest('.form-file');
                    showFileError(container, validation.error);
                    return;
                }
            }

            // Show progress overlay
            if (progressOverlay) {
                progressOverlay.hidden = false;
            }

            // Update button state
            var submitBtn = e.submitter || btnSend;
            if (submitBtn) {
                submitBtn.classList.add('btn--loading');
                submitBtn.disabled = true;
            }

            // Disable other buttons
            if (btnSend) btnSend.disabled = true;
            if (btnDraft) btnDraft.disabled = true;

            // Update progress text based on action
            if (progressText && e.submitter) {
                var action = e.submitter.value;
                if (action === 'draft') {
                    progressText.textContent = 'Enregistrement du brouillon...';
                } else {
                    progressText.textContent = 'Envoi en cours...';
                }
            }
        });
    }

    // Form validation styling
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        const inputs = form.querySelectorAll('.form-input, .form-textarea, .form-select');
        inputs.forEach(function(input) {
            input.addEventListener('invalid', function() {
                this.classList.add('form-input--error');
            });
            input.addEventListener('input', function() {
                if (this.validity.valid) {
                    this.classList.remove('form-input--error');
                }
            });
        });
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href');
            if (targetId !== '#') {
                const target = document.querySelector(targetId);
                if (target) {
                    e.preventDefault();
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            }
        });
    });

    // Confirmation dialogs for dangerous actions
    document.querySelectorAll('[data-confirm]').forEach(function(el) {
        el.addEventListener('click', function(e) {
            const message = this.dataset.confirm || 'Êtes-vous sûr ?';
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });

    console.log('QERDS UI initialized');
})();
