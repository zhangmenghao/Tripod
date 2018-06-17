# Gateway

About
--
Gateway project for netarchlab research. Cooperate with Baidu.

Runing Gateway
--
```
./go.sh
```

Evaluate Attack
--
```
sudo hping3 --rand-source 173.0.0.2 -I enp4s0f0 -i u15 -p 80 -A
sudo tcpreplay -K -l 10 -M 700 -i enp4s0f0 400w.pcap

```


