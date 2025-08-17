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

update:
	@echo "Downloading latest protocol files from Tesla vehicle-command repository..."
	curl -s -o car_server.proto "https://raw.githubusercontent.com/teslamotors/vehicle-command/main/pkg/protocol/protobuf/car_server.proto"
	curl -s -o common.proto "https://raw.githubusercontent.com/teslamotors/vehicle-command/main/pkg/protocol/protobuf/common.proto"
	curl -s -o errors.proto "https://raw.githubusercontent.com/teslamotors/vehicle-command/main/pkg/protocol/protobuf/errors.proto"
	curl -s -o keys.proto "https://raw.githubusercontent.com/teslamotors/vehicle-command/main/pkg/protocol/protobuf/keys.proto"
	curl -s -o managed_charging.proto "https://raw.githubusercontent.com/teslamotors/vehicle-command/main/pkg/protocol/protobuf/managed_charging.proto"
	curl -s -o signatures.proto "https://raw.githubusercontent.com/teslamotors/vehicle-command/main/pkg/protocol/protobuf/signatures.proto"
	curl -s -o universal_message.proto "https://raw.githubusercontent.com/teslamotors/vehicle-command/main/pkg/protocol/protobuf/universal_message.proto"
	curl -s -o vcsec.proto "https://raw.githubusercontent.com/teslamotors/vehicle-command/main/pkg/protocol/protobuf/vcsec.proto"
	curl -s -o vehicle.proto "https://raw.githubusercontent.com/teslamotors/vehicle-command/main/pkg/protocol/protobuf/vehicle.proto"
	@echo "Protocol files updated successfully!"
	@echo "Running make copy to regenerate headers and source files..."
	$(MAKE) copy
	@echo "Update complete!"
