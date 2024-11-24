import json
from channels.generic.websocket import AsyncWebsocketConsumer
from .models import ComputerProperties

class PropiedadesConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        propiedades = text_data_json['propiedades']

        ComputerProperties.objects.create(
            name=propiedades['Name'],
            operating_system=propiedades['OperatingSystem'],
            ram=propiedades['RAM'],
            motherboard=propiedades['Motherboard'],
            disk=propiedades['Disk'],
            last_update=propiedades['LastUpdate'],
            antivirus=propiedades['Antivirus'],
            antivirus_enabled=propiedades['AntivirusEnabled'],
            antivirus_updated=propiedades['AntivirusUpdated'],
            antivirus_update_frequency=propiedades['AntivirusUpdateFrequency'],
            antivirus_scan_frequency=propiedades['AntivirusScanFrequency'],
            user=propiedades['User'],
            password=propiedades['Password'],
            firewall=propiedades['Firewall'],
            domain=propiedades['Domain']
        )

        await self.send(text_data=json.dumps({
            'message': 'Propiedades recibidas y almacenadas',
        }))
