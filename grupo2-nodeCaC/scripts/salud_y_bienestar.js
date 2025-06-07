  document.addEventListener('DOMContentLoaded', () => {
    const botonesMuestra = document.querySelectorAll('.boton-muestra');
    botonesMuestra.forEach(button => {
        button.addEventListener('click', () => {
            const contenidoOculto = button.previousElementSibling;
            contenidoOculto.classList.toggle('hidden');
            button.textContent = contenidoOculto.classList.contains('hidden') ? 'Mostrar más' : 'Mostrar menos';
        });
    });
});