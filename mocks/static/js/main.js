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

    // File input enhancement
    const fileInputs = document.querySelectorAll('.form-file-input');
    fileInputs.forEach(function(input) {
        const label = input.nextElementSibling;
        const textEl = label.querySelector('.form-file-text');
        const originalText = textEl ? textEl.innerHTML : '';

        input.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
                const file = this.files[0];
                const size = (file.size / (1024 * 1024)).toFixed(2);
                if (textEl) {
                    textEl.innerHTML = '<strong>' + file.name + '</strong><br>' + size + ' Mo';
                }
                label.style.borderColor = 'var(--color-primary)';
                label.style.background = 'rgba(0, 0, 145, 0.04)';
            }
        });

        // Drag and drop
        label.addEventListener('dragover', function(e) {
            e.preventDefault();
            this.style.borderColor = 'var(--color-primary)';
            this.style.background = 'rgba(0, 0, 145, 0.08)';
        });

        label.addEventListener('dragleave', function(e) {
            e.preventDefault();
            this.style.borderColor = '';
            this.style.background = '';
        });

        label.addEventListener('drop', function(e) {
            e.preventDefault();
            this.style.borderColor = '';
            this.style.background = '';
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                input.files = e.dataTransfer.files;
                input.dispatchEvent(new Event('change'));
            }
        });
    });

    // Radio option styling
    const radioOptions = document.querySelectorAll('.radio-option');
    radioOptions.forEach(function(option) {
        const input = option.querySelector('input[type="radio"]');
        if (input) {
            function updateStyles() {
                radioOptions.forEach(function(opt) {
                    const radio = opt.querySelector('input[type="radio"]');
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
