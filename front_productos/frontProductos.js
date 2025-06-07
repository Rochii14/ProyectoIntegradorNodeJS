document.addEventListener("DOMContentLoaded", () => {
  const btnAgregarProducto = document.getElementById("btnAgregarProducto");
  const formProducto = document.getElementById("formProducto");
  const formAgregarProducto = document.getElementById("formAgregarProducto");

  if (document.getElementById("idalimentos")) {
    const contenedorProductos = document.querySelector("#idalimentos");

    /* FUNCION PARA OBTENER LOS DATOS DE NUESTRA API USANDO AXIOS */
    const cargarProductos = async () => {
      try {
        const respuesta = await axios.get("http://localhost:3030/productos/");
        const productos = respuesta.data;

        // Construir la cadena HTML dinámicamente
        let cad3 = '<div id="contenedor-productos" class="grid-container">';

        productos.forEach((producto) => {
          cad3 += `
                    <div class="card producto">
                        <div class="card-body">
                            <h3 class="card-title">${producto.nombre}</h3>
                            <img src="${producto.imagen}" alt="${producto.alt}">
                            <p class="card-text">
                                Precio: ${producto.precio}
                            </p>  
                            <a href="#" class="btn btn-card btn-editar" data-id="${producto.id}">Editar</a>
                            <a href="#" class="btn btn-card btn-eliminar" data-id="${producto.id}">Eliminar</a>
                            <div class="descripcion">
                                <p>${producto.descripcion}</p>
                            </div>
                        </div>
                    </div>
                `;
        });

        cad3 += "</div>";
        contenedorProductos.innerHTML = cad3;

        // Agregar eventos a los botones de editar y eliminar después de cargar los productos
        agregarEventosEditar();
        agregarEventosEliminar();
      } catch (error) {
        console.error("Error al obtener los productos", error);
      }
    };

    // Función para agregar eventos de eliminación a los botones de eliminar
    const agregarEventosEliminar = () => {
      document.querySelectorAll(".btn-eliminar").forEach((botonEliminar) => {
        botonEliminar.addEventListener("click", async (event) => {
          event.preventDefault();
          const idProducto = botonEliminar.getAttribute("data-id");
          console.log(idProducto);
          await borrarProducto(idProducto);
        });
      });
    };

    // Función para agregar eventos de edición a los botones de editar
    const agregarEventosEditar = () => {
      document.querySelectorAll(".btn-editar").forEach((botonEditar) => {
        botonEditar.addEventListener("click", (event) => {
          event.preventDefault();
          // Redirigir a la página de edición con el id del post en la URL
          const idProducto = botonEditar.getAttribute("data-id");
          console.log(idProducto);
          window.location.href = `formularioEditar.html?id=${idProducto}`;
        });
      });
    };

    // Función para borrar el producto
    const borrarProducto = async (id) => {
      try {
        await axios.delete(`http://localhost:3030/productos/${id}`);
        cargarProductos(); // Volver a cargar los productos después de eliminar
      } catch (error) {
        console.error(`Error al eliminar el producto: ${error}`);
      }
    };

    //FUNCIÓN PARA CREAR UN PRODUCTO
    // Agregar evento de clic al botón "Agregar producto"
    btnAgregarProducto.addEventListener("click", () => {
      // Alternar la visibilidad del formulario
      formProducto.classList.remove("oculto");
      formProducto.style.display = "block";
      formProducto.style.marginBottom = "10px";
    });
    // Agregar evento de clic al botón "Cancelar"
    btnCancelar.addEventListener("click", () => {
      formProducto.classList.add("oculto");
      formProducto.style.display = "none";
    });

    // Manejar el envío del formulario para agregar producto
    formAgregarProducto.addEventListener("submit", async (event) => {
      event.preventDefault();

      // Obtener los datos del formulario
      const producto = {
        nombre: document.getElementById("nombre").value,
        imagen: document.getElementById("imagen").value,
        alt: document.getElementById("alt").value,
        precio: document.getElementById("precio").value,
        descripcion: document.getElementById("descripcion").value,
      };

      try {
        // Enviar los datos del producto al servidor usando Axios
        const response = await axios.post(
          "http://localhost:3030/productos",
          producto
        );
        console.log(response.data);
        alert("Producto agregado exitosamente");

        // Ocultar el formulario y restablecer los valores
        formProducto.classList.add("oculto");
        formAgregarProducto.reset();

        // Recargar la lista de productos
        cargarProductos();
      } catch (error) {
        console.error("Hubo un error al agregar el producto:", error);
        alert("Hubo un error al agregar el producto. Intenta nuevamente.");
      }
    });

    // Llamar a la función para cargar los productos al cargar la página
    cargarProductos();
  }
});
