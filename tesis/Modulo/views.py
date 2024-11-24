from django.shortcuts import render,redirect,get_object_or_404
from django.contrib.auth import authenticate, login,logout
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import ComputerProperties,User,Rule, Monitoreo
from django.contrib.auth.hashers import make_password 
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User


def inicio(request):
    return render(request, 'index.html')
    
@login_required
def modulo(request):
    return render(request, 'modulo.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # Verificar la autenticación
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('modulo')
        else:
            # Agregar mensaje de error con más detalles
            messages.error(request, 'Nombre de usuario o contraseña incorrectos.')
            return render(request, 'login.html')
    
    return render(request, 'login.html')


def adicionar_usuario(request):
    if request.method == 'POST':
        username = request.POST.get('name')  # Usamos 'name' como username
        name = request.POST.get('name')  # Guardamos el nombre del usuario
        password = request.POST.get('password')

        # Validación de nombre de usuario
        if User.objects.filter(username=username).exists():
            return render(request, 'propiedades/adicionar_usuario.html', {'error': 'El nombre de usuario ya existe.'})

        # Crear el usuario
        user = User.objects.create_user(  # Usamos create_user para asegurar que se maneje la contraseña correctamente
            username=username,  # Ahora 'name' es el nombre de usuario
            password=password,
            first_name=name  # Se puede guardar el nombre real en 'first_name'
        )

        # Mensaje de éxito
        messages.success(request, 'Usuario añadido exitosamente.')

        return redirect('modulo')

    return render(request, 'propiedades/adicionar_usuario.html')



def modificar_usuario(request):
    if request.method == 'POST':
        user_id = request.POST['user_id']  # Obtener el ID del usuario
        try:
            usuario = User.objects.get(id=user_id)  # Corregir aquí a 'id'
            return render(request, 'propiedades/modificar_usuario.html', {'usuario': usuario})
        except User.DoesNotExist:
            return render(request, 'propiedades/modificar_usuario.html', {'error': 'Usuario no encontrado.'})
    return render(request, 'propiedades/modificar_usuario.html')

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User

def actualizar_usuario(request, id):
    # Asegúrate de que el usuario se obtiene por su ID
    usuario = get_object_or_404(User, id=id)

    if request.method == "POST":
        # Obtén los datos enviados por el formulario
        nuevo_username = request.POST.get('username')  # Aquí obtenemos el campo username
        nuevo_nombre = request.POST.get('first_name')  # Aquí obtenemos el nombre (opcional)
        nueva_password = request.POST.get('password')  # Aquí obtenemos la nueva contraseña (opcional)

        # Actualiza los campos correspondientes
        if nuevo_username:  # Si se envió un nuevo username, lo actualizamos
            usuario.username = nuevo_username

        if nuevo_nombre:  # Si se envió un nuevo nombre, lo actualizamos
            usuario.first_name = nuevo_nombre

        if nueva_password:  # Si se envió una nueva contraseña, la actualizamos
            usuario.set_password(nueva_password)

        # Guarda los cambios en el usuario
        usuario.save()

        # Renderizamos de nuevo con un mensaje de éxito
        return render(request, 'propiedades/modificar_usuario.html', {
            'success': 'Usuario actualizado correctamente',
            'usuario': usuario
        })

    # Si no es POST, simplemente muestra el formulario con el usuario actual
    return render(request, 'propiedades/modificar_usuario.html', {
        'usuario': usuario  # Enviamos el usuario para que se pueda editar
    })

def eliminar_usuario(request):
    if request.method == 'POST':
        user_id = request.POST['user_id']  # Obtener el ID desde el formulario
        try:
            # Obtener el usuario por el ID
            usuario = User.objects.get(id=user_id)
            # Redirigir a la vista de confirmación de eliminación con el ID del usuario
            return redirect('confirmar_eliminar_usuario', id=usuario.id)
        except User.DoesNotExist:
            return render(request, 'propiedades/eliminar_usuario.html', {'error': 'Usuario no encontrado.'})

    return render(request, 'propiedades/eliminar_usuario.html')


def confirmar_eliminar_usuario(request, id):
    if request.method == 'POST':
        # Aquí estamos usando `get_object_or_404` para obtener el usuario por el ID
        usuario = get_object_or_404(User, id=id)
        usuario.delete()  # Eliminar el usuario
        messages.success(request, 'Usuario eliminado exitosamente.')
        return redirect('listar_usuarios')  # Redirigir al listado de usuarios

    # Si no es un POST, simplemente renderizamos la página de confirmación
    return render(request, 'propiedades/eliminar_usuario.html', {'id': id})



def listar_usuarios(request):
    usuarios = User.objects.all()
    return render(request, 'propiedades/listar_usuarios.html', {'usuarios': usuarios})

def ver_detalles_usuario(request, id):
    # Obtener el usuario por su ID, si no existe lanza un error 404
    usuario = get_object_or_404(User, id=id)
    # Pasar los datos del usuario a la plantilla
    return render(request, 'propiedades/detalles_usuario.html', {'usuario': usuario})



def adicionar_computadora(request):
    if request.method == 'POST':
        computer_id = request.POST.get('computer_id')
        name = request.POST.get('name')
        lab = request.POST.get('lab')
        ip_address = request.POST.get('ip_address')
        disk = request.POST.get('disk')
        motherboard = request.POST.get('motherboard')
        ram = request.POST.get('ram')
        operating_system = request.POST.get('operating_system')
        last_update = request.POST.get('last_update')
        antivirus = request.POST.get('antivirus')
        antivirus_enabled = request.POST.get('antivirus_enabled') == 'yes'
        antivirus_updated = request.POST.get('antivirus_updated') == 'yes'
        firewall = request.POST.get('firewall')
        firewall_enabled = request.POST.get('firewall_enabled') == 'yes'
        browser = request.POST.get('browser')
        domain = request.POST.get('domain')

        # Guardar el objeto
        ComputerProperties.objects.create(
            computer_id=computer_id,
            name=name,
            lab=lab,
            ip_address=ip_address,
            disk=disk,
            motherboard=motherboard,
            ram=ram,
            operating_system=operating_system,
            last_update=last_update,
            antivirus=antivirus,
            antivirus_enabled=antivirus_enabled,
            antivirus_updated=antivirus_updated,
            firewall=firewall,
            firewall_enabled=firewall_enabled,
            browser=browser,
            domain=domain
        )
        return render(request, 'propiedades/adicionar_computadora.html', {'success': 'Computadora añadida exitosamente.'})

    return render(request, 'propiedades/adicionar_computadora.html')





def modificar_computadora(request):
    if request.method == 'POST' and 'load_computer' in request.POST:
        computer_id = request.POST.get('computer_id')
        if computer_id.isdigit():  # Verificar que el ID sea numérico
            try:
                computadora = ComputerProperties.objects.get(computer_id=int(computer_id))
                return render(request, 'propiedades/modificar_computadora.html', {'computadora': computadora})
            except ComputerProperties.DoesNotExist:
                return render(request, 'propiedades/modificar_computadora.html', {'error': 'Computadora no encontrada.'})
        else:
            return render(request, 'propiedades/modificar_computadora.html', {'error': 'ID de computadora inválido.'})
    return render(request, 'propiedades/modificar_computadora.html')

def actualizar_computadora(request, id):
    if request.method == 'POST':
        computadora = get_object_or_404(ComputerProperties, id=id)
        computadora.name = request.POST['name']
        computadora.lab = request.POST['lab']
        computadora.ip_address = request.POST['ip_address']
        computadora.operating_system = request.POST['operating_system']
        computadora.disk = request.POST['disk']
        computadora.motherboard = request.POST['motherboard']
        computadora.ram = request.POST['ram']
        computadora.last_update = request.POST['last_update']
        computadora.antivirus = request.POST['antivirus']
        computadora.antivirus_enabled = request.POST['antivirus_enabled'] == 'yes'
        computadora.antivirus_updated = request.POST['antivirus_updated'] == 'yes'
        computadora.firewall = request.POST['firewall']
        computadora.firewall_enabled = request.POST['firewall_enabled'] == 'yes'
        computadora.browser = request.POST['browser']
        computadora.domain = request.POST['domain']
        computadora.save()
        
        return render(request, 'propiedades/modificar_computadora.html', {'computadora': computadora, 'success': 'Computadora actualizada exitosamente.'})
    return render(request, 'propiedades/modificar_computadora.html')




def eliminar_computadora(request):
    if request.method == 'POST' and 'search_computer' in request.POST:
        computer_id = request.POST.get('computer_id')
        if computer_id.isdigit():  # Verificar que el ID sea numérico
            try:
                computadora = ComputerProperties.objects.get(computer_id=int(computer_id))
                return render(request, 'propiedades/eliminar_computadora.html', {'computadora': computadora})
            except ComputerProperties.DoesNotExist:
                return render(request, 'propiedades/eliminar_computadora.html', {'error': 'Computadora no encontrada.'})
        else:
            return render(request, 'propiedades/eliminar_computadora.html', {'error': 'ID de computadora inválido.'})
    return render(request, 'propiedades/eliminar_computadora.html')

def confirmar_eliminar_computadora(request, id):
    if request.method == 'POST':
        computadora = get_object_or_404(ComputerProperties, id=id)
        computadora.delete()
        return render(request, 'propiedades/eliminar_computadora.html', {'success': 'Computadora eliminada exitosamente.'})
    return render(request, 'propiedades/eliminar_computadora.html')




def listar_computadoras(request):
    computadoras = ComputerProperties.objects.all()
    return render(request, 'propiedades/listar_computadoras.html', {'computadoras': computadoras})











def realizar_monitoreo(request):
    # Obtener los criterios de filtrado desde la solicitud GET
    filter_select = request.GET.get('filter-select')
    filter_value = request.GET.get(filter_select) if filter_select else None

    # Filtrar computadoras según los criterios seleccionados
    computadoras = ComputerProperties.objects.all()

    if filter_select and filter_value:
        if filter_select == 'lab':
            computadoras = computadoras.filter(lab=filter_value)
        elif filter_select == 'ip':
            computadoras = computadoras.filter(ip_address=filter_value)
        elif filter_select == 'os':
            computadoras = computadoras.filter(operating_system=filter_value)
        elif filter_select == 'ram':
            computadoras = computadoras.filter(ram=filter_value)
        elif filter_select == 'microprocesador':
            computadoras = computadoras.filter(microprocessor=filter_value)
        elif filter_select == 'motherboard':
            computadoras = computadoras.filter(motherboard=filter_value)
        elif filter_select == 'disk':
            computadoras = computadoras.filter(disk=filter_value)
        elif filter_select == 'last_update':
            computadoras = computadoras.filter(last_update__lte=filter_value)
    
    selected_rules = Rule.objects.filter(id__in=request.session.get('selected_rules', []))
    incumplimientos_totales = []
    computadoras_monitoreadas = []

    for computadora in computadoras:
        reglas_incumplidas = []
        last_update_naive = computadora.last_update.replace(tzinfo=None)  # Convertir a naive datetime

        if selected_rules.filter(name='Sistema Operativo Actualizado').exists():
            if (datetime.now() - last_update_naive) > timedelta(days=10):
                reglas_incumplidas.append('Sistema operativo desactualizado más de 10 días')
        if selected_rules.filter(name='Antivirus Activado').exists():
            if not computadora.antivirus_enabled:
                reglas_incumplidas.append('Antivirus no activado')
        if selected_rules.filter(name='Antivirus Actualizado').exists():
            if not computadora.antivirus_updated:
                reglas_incumplidas.append('Antivirus desactualizado')
        if selected_rules.filter(name='Firewall Activado').exists():
            if not computadora.firewall_enabled:
                reglas_incumplidas.append('Firewall no activado')
        if selected_rules.filter(name='Navegador Firefox').exists():
            if computadora.browser != "Firefox":
                reglas_incumplidas.append('El navegador no es Firefox')

        if reglas_incumplidas:
            computadoras_monitoreadas.append(computadora)
            incumplimientos_totales.append({
                'computer_id': computadora.computer_id,
                'name': computadora.name,
                'incumplimientos': reglas_incumplidas
            })

    # Crear el objeto Monitoreo solo si hay computadoras monitoreadas
    if computadoras_monitoreadas:
        monitoreo = Monitoreo.objects.create()
        monitoreo.computers_monitored.set(computadoras_monitoreadas)
        monitoreo.incumplimientos_detected = incumplimientos_totales
        monitoreo.save()

    laboratorios = ComputerProperties.objects.values_list('lab', flat=True).distinct()
    sistemas_operativos = ComputerProperties.objects.values_list('operating_system', flat=True).distinct()

    return render(request, 'propiedades/realizar_monitoreo.html', {
        'computadoras': computadoras,
        'laboratorios': laboratorios,
        'sistemas_operativos': sistemas_operativos,
        'incumplimientos': incumplimientos_totales
    })








def verificar_incumplimientos(request):
    # Mover la importación aquí para evitar importaciones circulares
    from .models import ComputerProperties, Rule

    # Verifica si estas reglas ya existen en tu base de datos, si no existen, añádelas
    rules = [
        {'name': 'Sistema Operativo Actualizado', 'description': 'El sistema operativo debe estar actualizado'},
        {'name': 'Antivirus Activado', 'description': 'El antivirus debe estar activado'},
        {'name': 'Antivirus Actualizado', 'description': 'El antivirus debe estar actualizado'},
        {'name': 'Firewall Activado', 'description': 'El firewall debe estar activado'},
        {'name': 'Navegador Firefox', 'description': 'El navegador debe ser Firefox'}
    ]

    for rule in rules:
        Rule.objects.get_or_create(name=rule['name'], defaults={'description': rule['description']})

    computadoras = ComputerProperties.objects.all()
    selected_rules = Rule.objects.filter(id__in=request.session.get('selected_rules', []))
    incumplimientos = []

    for computadora in computadoras:
        reglas_incumplidas = []
        last_update_naive = computadora.last_update.replace(tzinfo=None)  # Convertir a naive datetime
        
        if selected_rules.filter(name='Sistema Operativo Actualizado').exists():
            if (datetime.now() - last_update_naive) > timedelta(days=10):
                reglas_incumplidas.append('Sistema operativo desactualizado más de 10 días')
        if selected_rules.filter(name='Antivirus Activado').exists():
            if not computadora.antivirus_enabled:
                reglas_incumplidas.append('Antivirus no activado')
        if selected_rules.filter(name='Antivirus Actualizado').exists():
            if not computadora.antivirus_updated:
                reglas_incumplidas.append('Antivirus desactualizado')
        if selected_rules.filter(name='Firewall Activado').exists():
            if not computadora.firewall_enabled:
                reglas_incumplidas.append('Firewall no activado')
        if selected_rules.filter(name='Navegador Firefox').exists():
            if computadora.browser != "Firefox":
                reglas_incumplidas.append('El navegador no es Firefox')
        
        if reglas_incumplidas:
            incumplimientos.append({'computer': computadora, 'reglas': reglas_incumplidas})
        else:
            incumplimientos.append({'computer': computadora, 'reglas': ['No se detectó ningún incumplimiento']})

    return render(request, 'propiedades/incumplimientos.html', {'incumplimientos': incumplimientos})




def exportar_pdf(request):
    # Crear respuesta de PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="monitoreo.pdf"'

    # Crear canvas de ReportLab
    pdf = canvas.Canvas(response, pagesize=letter)
    width, height = letter

    # Título del PDF
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(200, height - 50, "Resultados del Monitoreo de Computadoras")

    pdf.setFont("Helvetica", 12)
    y = height - 100

    computadoras = ComputerProperties.objects.all()
    for computadora in computadoras:
        pdf.drawString(30, y, f"ID: {computadora.computer_id} - Nombre: {computadora.name}")
        pdf.drawString(30, y - 15, f"Laboratorio: {computadora.lab} - IP: {computadora.ip_address}")
        pdf.drawString(30, y - 30, f"Sistema Operativo: {computadora.operating_system} - Última Actualización: {computadora.last_update}")
        pdf.drawString(30, y - 45, f"Antivirus Activo: {'Sí' if computadora.antivirus_enabled else 'No'}")
        pdf.drawString(30, y - 60, f"Antivirus Actualizado: {'Sí' if computadora.antivirus_updated else 'No'}")
        pdf.drawString(30, y - 75, f"Firewall Activo: {'Sí' if computadora.firewall_enabled else 'No'}")
        pdf.drawString(30, y - 90, f"Navegador: {computadora.browser}")
        pdf.drawString(30, y - 105, f"Dominio: {computadora.domain}")
        y -= 120
        
        reglas_incumplidas = []
        last_update_naive = computadora.last_update.replace(tzinfo=None)  # Convertir a naive datetime
        if (datetime.now() - last_update_naive) > timedelta(days=10):
            reglas_incumplidas.append('Sistema operativo desactualizado más de 10 días')
        if not computadora.antivirus_enabled:
            reglas_incumplidas.append('Antivirus no activado')
        if not computadora.antivirus_updated:
            reglas_incumplidas.append('Antivirus desactualizado')
        if not computadora.firewall_enabled:
            reglas_incumplidas.append('Firewall no activado')
        if computadora.browser != "Firefox":
            reglas_incumplidas.append('El navegador no es Firefox')
        
        if reglas_incumplidas:
            pdf.drawString(30, y, "Incumplimientos:")
            y -= 15
            for regla in reglas_incumplidas:
                pdf.drawString(50, y, f"- {regla}")
                y -= 15
        else:
            pdf.drawString(30, y, "No se detectó ningún incumplimiento.")
            y -= 15

        y -= 20
        if y < 50:
            pdf.showPage()
            y = height - 100

    pdf.save()
    return response










def listar_reglas(request):
    reglas = Rule.objects.all()
    selected_rules = request.session.get('selected_rules', [])

    if request.method == 'POST':
        selected_rules = request.POST.getlist('rules')
        request.session['selected_rules'] = selected_rules
    
    return render(request, 'propiedades/listar_reglas.html', {'reglas': reglas, 'selected_rules': selected_rules})






def listar_monitoreos(request):
    from .models import Monitoreo  # Importar dentro de la función
    monitoreos = Monitoreo.objects.all()
    return render(request, 'propiedades/listar_monitoreos.html', {'monitoreos': monitoreos})

def ver_detalles_monitoreo(request, id):
    from .models import Monitoreo  # Importar dentro de la función
    monitoreo = get_object_or_404(Monitoreo, id=id)
    return render(request, 'propiedades/detalles_monitoreo.html', {'monitoreo': monitoreo})

def eliminar_monitoreo(request, id):
    from .models import Monitoreo  # Importar dentro de la función
    monitoreo = get_object_or_404(Monitoreo, id=id)
    monitoreo.delete()
    return redirect('listar_monitoreos')






def enviar_resultados(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        computadoras = ComputerProperties.objects.all()
        incumplimientos_totales = []  # Esta variable debe ser rellenada con los detalles del monitoreo

        # Preparar el mensaje de correo
        subject = 'Resultados del Monitoreo de Computadoras'
        message = 'Adjunto encontrarás los resultados del monitoreo de computadoras:\n\n'
        for detalle in incumplimientos_totales:
            message += f"ID: {detalle['computer_id']}, Nombre: {detalle['name']}\n"
            for incumplimiento in detalle['incumplimientos']:
                message += f"- {incumplimiento}\n"
            message += '\n'

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

        return redirect('listar_computadoras')
    return render(request, 'propiedades/listar_computadoras.html')
