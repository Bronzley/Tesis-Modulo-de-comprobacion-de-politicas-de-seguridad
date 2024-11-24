from django.urls import path
from .views import inicio,modulo,login_view,adicionar_usuario,modificar_usuario,actualizar_usuario,eliminar_usuario,confirmar_eliminar_usuario,listar_usuarios,adicionar_computadora,modificar_computadora, actualizar_computadora,eliminar_computadora,confirmar_eliminar_computadora,listar_computadoras, realizar_monitoreo,verificar_incumplimientos,exportar_pdf,listar_reglas,listar_monitoreos,ver_detalles_monitoreo, eliminar_monitoreo, enviar_resultados, ver_detalles_usuario
from django.contrib.auth import views as auth_views



urlpatterns = [
path('', inicio, name='inicio'),
path('modulo/',modulo, name='modulo'),
path('login/', login_view, name='login'),
path('logout/', auth_views.LogoutView.as_view(next_page='inicio'), name='logout'),
path('usuarios/adicionar/', adicionar_usuario, name='adicionar_usuario'),
path('usuarios/modificar/', modificar_usuario, name='modificar_usuario'), 
path('usuarios/actualizar/<int:id>/', actualizar_usuario, name='actualizar_usuario'),
path('usuarios/eliminar/', eliminar_usuario, name='eliminar_usuario'),
path('usuarios/confirmar_eliminar/<int:id>/', confirmar_eliminar_usuario, name='confirmar_eliminar_usuario'),
path('usuarios/listar/', listar_usuarios, name='listar_usuarios'),
path('computadoras/adicionar/', adicionar_computadora, name='adicionar_computadora'),  
path('computadoras/modificar/', modificar_computadora, name='modificar_computadora'),
path('computadoras/actualizar/<int:id>/', actualizar_computadora, name='actualizar_computadora'),
path('computadoras/eliminar/', eliminar_computadora, name='eliminar_computadora'),
path('computadoras/confirmar_eliminar/<int:id>/', confirmar_eliminar_computadora, name='confirmar_eliminar_computadora'),
path('computadoras/listar/', listar_computadoras, name='listar_computadoras'),
path('monitoreos/realizar/', realizar_monitoreo, name='realizar_monitoreo'),
path('monitoreos/verificar/', verificar_incumplimientos, name='verificar_incumplimientos'),
path('monitoreos/exportar/', exportar_pdf, name='exportar_pdf'),  # Exportar Resultados en PDF
path('reglas/listar/', listar_reglas, name='listar_reglas'),  # Nueva URL para listar reglas
path('monitoreos/listar/', listar_monitoreos, name='listar_monitoreos'),
path('monitoreos/detalles/<int:id>/', ver_detalles_monitoreo, name='ver_detalles_monitoreo'),  # Ver detalles del monitoreo
path('monitoreos/eliminar/<int:id>/', eliminar_monitoreo, name='eliminar_monitoreo'),  # Eliminar monitoreo
path('enviar_resultados/', enviar_resultados, name='enviar_resultados'),  # Nueva URL para enviar resultados
path('usuarios/detalles/<int:id>/', ver_detalles_usuario, name='ver_detalles_usuario'),
]





    
   


    



