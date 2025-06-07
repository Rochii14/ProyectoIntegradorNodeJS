const formulario = document.getElementById('formulario');
const inputs = document.querySelectorAll('#formulario input');
const select = document.getElementById('tipoConsulta');
const textarea = document.getElementById('consulta');

const expresiones = {
	nombre: /^[a-zA-ZÀ-ÿ]{3,}\s[a-zA-ZÀ-ÿ\s]{1,20}$/, // Letras y espacios, pueden llevar acentos.
	correo: /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/,
	telefono: /^\d{7,14}$/, // 7 a 14 numeros.
	textarea: /^.{1,1500}$/ // Mínimo 1 y máximo 1500 caracteres para el textarea
};

const campos = {
	nombre: false,
	correo: false,
	telefono: false,
	tipoConsulta: false,
	consulta: false,
};

const validarFormulario = (e) => {
	switch (e.target.name) {
		case "nombre":
			validarCampo(expresiones.nombre, e.target, 'nombre');
			break;
		case "correo":
			validarCampo(expresiones.correo, e.target, 'correo');
			break;
		case "telefono":
			validarCampo(expresiones.telefono, e.target, 'telefono');
			break;
		case "tipoConsulta":
			validarSelect(e.target, 'tipoConsulta');
			break;
		case "consulta":
			validarTextarea(expresiones.textarea, e.target, 'consulta');
			break;
	}
};

const validarCampo = (expresion, input, campo) => {
	if (expresion.test(input.value)) {
		document.getElementById(`grupo__${campo}`).classList.remove('formulario__grupo-incorrecto');
		document.getElementById(`grupo__${campo}`).classList.add('formulario__grupo-correcto');
		document.querySelector(`#grupo__${campo} i`).classList.add('fa-check-circle');
        document.querySelector(`#grupo__${campo} i`).classList.remove('fa-times-circle');
		document.querySelector(`#grupo__${campo} .formulario__input-error`).classList.remove('formulario__input-error-activo');
		campos[campo] = true;
	} else {
		document.getElementById(`grupo__${campo}`).classList.add('formulario__grupo-incorrecto');
		document.getElementById(`grupo__${campo}`).classList.remove('formulario__grupo-correcto');
		document.querySelector(`#grupo__${campo} i`).classList.add('fa-times-circle');
        document.querySelector(`#grupo__${campo} i`).classList.remove('fa-check-circle');
		document.querySelector(`#grupo__${campo} .formulario__input-error`).classList.add('formulario__input-error-activo');
		campos[campo] = false;
	}
};


//-------------------- VALIDACION SELECT
const validarSelect = (select, campo) => {
    if(select.value !== ''){
        campos[campo] = true;
        document.getElementById(`grupo__${campo}`).classList.remove('formulario__grupo-incorrecto');
        document.getElementById(`grupo__${campo}`).classList.add('formulario__grupo-correcto');
		document.querySelector(`#grupo__${campo} .formulario__input-error`).classList.remove('formulario__input-error-activo');

    } else {
        campos[campo] = false;
        document.getElementById(`grupo__${campo}`).classList.add('formulario__grupo-incorrecto');
        document.getElementById(`grupo__${campo}`).classList.remove('formulario__grupo-correcto');
        document.getElementById(`tipoConsulta`).classList.add('formulario__input');
		document.querySelector(`#grupo__${campo} .formulario__input-error`).classList.add('formulario__input-error-activo');

    }
};

//---------------------- VALIDACION TEXTAREA
const validarTextarea = (expresion, input, campo) => {
	if (expresion.test(input.value)) {
		document.getElementById(`grupo__${campo}`).classList.remove('formulario__grupo-incorrecto');
		document.getElementById(`grupo__${campo}`).classList.add('formulario__grupo-correcto');
		document.querySelector(`#grupo__${campo} .formulario__input-error`).classList.remove('formulario__input-error-activo');
		campos[campo] = true;
	} else {
		document.getElementById(`grupo__${campo}`).classList.add('formulario__grupo-incorrecto');
		document.getElementById(`grupo__${campo}`).classList.remove('formulario__grupo-correcto');
		document.querySelector(`#grupo__${campo} .formulario__input-error`).classList.add('formulario__input-error-activo');
		campos[campo] = false;
	}
};

inputs.forEach((input) => {
	input.addEventListener('keyup', validarFormulario);
	input.addEventListener('blur', validarFormulario);
	textarea.addEventListener('keyup', validarFormulario);
	textarea.addEventListener('blur', validarFormulario);
});

select.addEventListener('change', validarFormulario);
select.addEventListener('blur', (e) => validarSelect(e.target, 'tipoConsulta')); // Añadir validación al perder el foco


//Contador de caracteres
function contador(){
        let val = document.getElementById('consulta');
        let cantidad = val.value.length;
        document.getElementById('resp').innerHTML = `${cantidad}/1500`;
		document.getElementById(`caracteres`).classList.add('caracteres-activado');
}

formulario.addEventListener('submit', (e) => {
	e.preventDefault();

	const terminos = document.getElementById('terminos');
	if (campos.nombre && campos.correo && campos.telefono && campos.tipoConsulta && campos.consulta && terminos.checked) {
		formulario.reset();

		document.getElementById('formulario__mensaje-exito').classList.add('formulario__mensaje-exito-activo');
		setTimeout(() => {
			document.getElementById('formulario__mensaje-exito').classList.remove('formulario__mensaje-exito-activo');
		}, 3000);

		document.querySelectorAll('.formulario__grupo-correcto').forEach((icono) => {
			icono.classList.remove('formulario__grupo-correcto');
		});

		//Eliminar caracteres del textarea
		document.getElementById(`caracteres`).classList.remove('caracteres-activado');

		// Eliminar el mensaje de error
		const mensajeError = document.getElementById('formulario__mensaje');
		if (mensajeError) {
			setTimeout(() => {
				mensajeError.remove();
			}, 800);
		}
	} else {
		document.getElementById('formulario__mensaje').classList.add('formulario__mensaje-activo');
	}
});



