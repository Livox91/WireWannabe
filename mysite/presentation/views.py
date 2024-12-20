from django.shortcuts import render
from mysite.application.WireWannabe import getInterfaces ,capture_packets, display_stored_packets
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from mysite.middleware.Config import Config

packetCap = Config()

def first(request):
    return render(request, 'mainPage.html')

async def second(request):    
    interfaces = getInterfaces()
    return render(request,'secondPage.html',{'choices': interfaces})

def third(request):
    choices = ["TCP", "UDP", "ICMP", "ALL"]
    return render(request,'thirdPage.html',{'choices':choices})

def fourth(request):
    return render(request,'fourthPage.html')

def display(request):
    packets = display_stored_packets()
    return render(request,'display.html',{'packets':packets})

@csrf_exempt 
def recieveData(request):

    if request.method == "POST":
        try:
            
            data = json.loads(request.body)  # Extract JSON data from request
            if(data.get('interface')):
                packetCap.interface = data.get('interface')
            if(data.get('bpfFilter')):
                packetCap.bpfFilter = data.get('bpfFilter')
            if(data.get('output_file')):
                packetCap.output_file = data.get('output_file')
            if(data.get('count')):
                packetCap.count = int (data.get('count'))
            
            
            #ensure all the data is present and pass it to the capture_packets function
            # if packetCap.interface and packetCap.bpfFilter and packetCap.output_file and packetCap.count:
            #     capture_packets(packetCap.interface, packetCap.count, packetCap.bpfFilter, packetCap.output_file)
            # else:
            #     return JsonResponse({"status": "error", "message": "Missing required fields"}, status=400)
            
            
            
            # Return a JSON response
            return JsonResponse({"status": "success", "message": "Data received", "data": data, "Capturing Packets" : "True"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)
    return JsonResponse({"status": "error", "message": "Invalid request method"}, status=405)

def runScript(request):
    
    capture_packets(packetCap.interface, packetCap.count, packetCap.bpfFilter, packetCap.output_file)
    return JsonResponse({"status": "success", "message": "Script Running", "Capturing Packets" : "True"})