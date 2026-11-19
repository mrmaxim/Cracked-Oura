"""Transport selection shared by the one-shot sync and persistent daemon."""
import os


def create_ring(progress=None):
    transport = os.environ.get("OURA_TRANSPORT", "nordic").lower()
    if transport == "native":
        from oura_bleak import NativeOuraRing
        return NativeOuraRing(address=os.environ.get("OURA_ADDRESS"), progress=progress)
    if transport == "nordic":
        from oura_ring import OuraRing, pick_port
        return OuraRing(pick_port(None))
    raise ValueError("OURA_TRANSPORT must be 'native' or 'nordic'")
