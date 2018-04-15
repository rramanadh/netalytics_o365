import json
import stomp
import eventlet
from st2reactor.sensor.base import Sensor


class AMQMessageProcessor(stomp.ConnectionListener):
    def __init__(self, sensor_class):
        self.sensorclass = sensor_class

    def on_error(self, headers, body):
        pass

    def on_message(self, headers, msg):
        if isinstance(msg, str) or isinstance(msg, unicode):
            msg = json.loads(msg)
        self.sensorclass._logger.debug("Received Message:%s" % msg)
        self.sensorclass.sensor_service.dispatch(trigger='netalytics_o365.mqevent', payload=msg)


class O365Sensor(Sensor):
    def __init__(self, sensor_service, config):
        super(O365Sensor, self).__init__(sensor_service=sensor_service, config=config)
        self._logger = self.sensor_service.get_logger(name=self.__class__.__name__)
        self._stop = False
        self.connection = None

    def setup(self):
        host = "b-096c1bcf-5e10-4578-a379-d7c188a02841-1.mq.us-east-2.amazonaws.com"
        port = 61614
        username = "cwunite"
        password = "cwunite@1234"
        queueName = "/queue/stackstorm"
        self.connection = stomp.Connection10(host_and_ports=[(host, port)], use_ssl=True)
        self.connection.connect(username, password)
        self.connection.set_listener('netalytics', AMQMessageProcessor(self))
        self.connection.subscribe(queueName)

    def run(self):
        while not self._stop:
            eventlet.sleep(60)

    def cleanup(self):
        self.connection.disconnect()

    # Methods required for programmable sensors.
    def add_trigger(self, trigger):
        pass

    def update_trigger(self, trigger):
        pass

    def remove_trigger(self, trigger):
        pass