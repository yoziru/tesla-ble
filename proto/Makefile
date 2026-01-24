.DEFAULT_GOAL := help

update:
	@echo "Getting the latest commit hash from Tesla vehicle-command repository..."
	@echo "Git commit hash: $$(git ls-remote https://github.com/teslamotors/vehicle-command.git main | cut -f1)"
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

generate:
	@echo "Regenerating protobuf files..."
	mkdir -p ../generated/src ../generated/include/google/protobuf
	python3 ../build/_deps/nanopb-src/generator/nanopb_generator.py --output-dir=../generated/src *.proto google/protobuf/*.proto
	@echo "Moving generated headers to generated/include..."
	mv ../generated/src/*.pb.h ../generated/include/
	mv ../generated/src/google/protobuf/*.pb.h ../generated/include/google/protobuf/
	@echo "Reformatting generated files..."
	clang-format -i ../generated/include/*.h ../generated/include/google/protobuf/*.h ../generated/src/*.c
	@echo "Protobuf files regenerated and formatted successfully!"

help:
	@echo "Makefile commands:"
	@echo "  update    - Download the latest protocol files from the Tesla vehicle-command repo"
	@echo "  generate - Regenerate protobuf C files from .proto files"