#!/usr/bin/env python3
"""A genuinely separate process for private-bus authorization tests."""
import asyncio
import json
import os
import sys
from dbus_next import Message, MessageType, Variant
from dbus_next.aio import MessageBus


async def main():
    bus = await MessageBus(bus_address=sys.argv[1]).connect()
    print(json.dumps({'pid': os.getpid(), 'owner': bus.unique_name}), flush=True)
    try:
        while line := await asyncio.to_thread(sys.stdin.readline):
            request = json.loads(line)
            if request.get('reconnect'):
                bus.disconnect()
                await bus.wait_for_disconnect()
                bus = await MessageBus(bus_address=sys.argv[1]).connect()
                print(json.dumps({'pid': os.getpid(), 'owner': bus.unique_name}), flush=True)
                continue
            if executable := request.get('exec'):
                bus.disconnect()
                await bus.wait_for_disconnect()
                os.execv(executable, [executable, __file__, sys.argv[1]])
            request['body'] = [Variant(v['variant'], v['value']) if isinstance(v, dict) and 'variant' in v else v
                               for v in request.get('body', [])]
            reply = await bus.call(Message(**request))
            print(json.dumps({'error': reply.error_name if reply.message_type == MessageType.ERROR else None,
                              'body': reply.body}, default=lambda v: v.value if isinstance(v, Variant) else list(v)), flush=True)
    finally:
        bus.disconnect()


asyncio.run(main())
