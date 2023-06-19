import websockets
import asyncio

async def sink(websocket, path):

    try:
        async for message in websocket:
            print(message)

    except Exception as e:
        print("Exception: "+str(type(e).__name__))


start_server = websockets.serve(sink, "localhost", 3000)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
