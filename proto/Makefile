.DEFAULT_GOAL := generate

generate_raw:
	mkdir -p out
	nanopb_generator *.proto --output-dir=out/

fix:
	sed '/google\/protobuf\/timestamp/d' out/car_server.pb.h > out/car_server.pb.h.tmp
	mv out/car_server.pb.h.tmp out/car_server.pb.h
	sed '/google\/protobuf\/timestamp/d' out/vehicle.pb.h > out/vehicle.pb.h.tmp
	mv out/vehicle.pb.h.tmp out/vehicle.pb.h

generate: generate_raw fix

copy: generate
	cp out/*.pb.h ../include
	cp out/*.pb.c ../src
	rm -rf out
