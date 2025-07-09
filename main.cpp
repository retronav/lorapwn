
#include "mbed.h"
#include "platform/mbed_thread.h"
#include <vector>
#include <cstdint>
#include <chrono>
#include <ctime>

// SX1272 Register definitions
#define REG_FIFO                    0x00
#define REG_OP_MODE                 0x01
#define REG_FRF_MSB                 0x06
#define REG_FRF_MID                 0x07
#define REG_FRF_LSB                 0x08
#define REG_PA_CONFIG               0x09
#define REG_LNA                     0x0C
#define REG_FIFO_ADDR_PTR           0x0D
#define REG_FIFO_TX_BASE_ADDR       0x0E
#define REG_FIFO_RX_BASE_ADDR       0x0F
#define REG_FIFO_RX_CURRENT_ADDR    0x10
#define REG_IRQ_FLAGS_MASK          0x11
#define REG_IRQ_FLAGS               0x12
#define REG_RX_NB_BYTES             0x13
#define REG_PKT_SNR_VALUE           0x19
#define REG_PKT_RSSI_VALUE          0x1A
#define REG_MODEM_CONFIG_1          0x1D
#define REG_MODEM_CONFIG_2          0x1E
#define REG_SYMB_TIMEOUT_LSB        0x1F
#define REG_PREAMBLE_MSB            0x20
#define REG_PREAMBLE_LSB            0x21
#define REG_PAYLOAD_LENGTH          0x22
#define REG_MODEM_CONFIG_3          0x26
#define REG_SYNC_WORD               0x39
#define REG_DIO_MAPPING_1           0x40
#define REG_VERSION                 0x42
#define REG_DETECTION_OPTIMIZE      0x31
#define REG_DETECTION_THRESHOLD     0x37

// Operating modes
#define MODE_LONG_RANGE_MODE        0x80
#define MODE_SLEEP                  0x00
#define MODE_STDBY                  0x01
#define MODE_RXCONTINUOUS           0x05

// IRQ flags
#define IRQ_RX_DONE_MASK            0x40
#define IRQ_PAYLOAD_CRC_ERROR_MASK  0x20

// mDot pin definitions
#define RADIO_RESET     PC_2
#define RADIO_MOSI      PB_15
#define RADIO_MISO      PB_14
#define RADIO_SCLK      PB_13
#define RADIO_NSS       PB_12
#define RADIO_DIO_0     PA_0

// Serial for debug
BufferedSerial pc(USBTX, USBRX, 115200);

// Packet structure
struct LoRaPacket {
    uint32_t timestamp;
    uint32_t frequency;
    uint8_t sf;
    int16_t rssi;
    int8_t snr;
    uint8_t payload[255];
    uint8_t payload_size;
    uint32_t dev_addr;
    uint8_t mtype;
    bool is_join_request;
    bool crc_error;
};

class SX1272LoRaSniffer {
private:
    SPI spi;
    DigitalOut nss;
    DigitalOut reset;
    InterruptIn dio0;
    
    std::vector<uint32_t> frequencies;
    std::vector<uint8_t> spreading_factors;
    std::vector<LoRaPacket> packet_log;
    
    volatile bool packet_received;
    bool running;
    uint32_t current_freq_index;
    uint32_t current_sf_index;
    
    // Helper function for serial output
    void serial_printf(const char* format, ...) {
        char buffer[256];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        pc.write(buffer, strlen(buffer));
    }
    
    // Helper function for reading single character
    char serial_getc() {
        char c;
        pc.read(&c, 1);
        return c;
    }
    
public:
    SX1272LoRaSniffer() : 
        spi(RADIO_MOSI, RADIO_MISO, RADIO_SCLK),
        nss(RADIO_NSS),
        reset(RADIO_RESET),
        dio0(RADIO_DIO_0),
        packet_received(false),
        running(false),
        current_freq_index(0),
        current_sf_index(0) {
        
        // EU868 frequencies
        frequencies.push_back(868100000);
        frequencies.push_back(868300000);
        frequencies.push_back(868500000);
        frequencies.push_back(867100000);
        frequencies.push_back(867300000);
        frequencies.push_back(867500000);
        frequencies.push_back(867700000);
        frequencies.push_back(867900000);
        
        spreading_factors.push_back(7);
        spreading_factors.push_back(8);
        spreading_factors.push_back(9);
        spreading_factors.push_back(10);
        spreading_factors.push_back(11);
        spreading_factors.push_back(12);
        
        // Configure SPI
        spi.format(8, 0);
        spi.frequency(8000000);
        
        // Setup interrupt
        dio0.rise(callback(this, &SX1272LoRaSniffer::on_dio0_rise));
        
        // Initialize radio
        init_radio();
    }
    
    void init_radio() {
        // Reset radio
        reset = 0;
        ThisThread::sleep_for(10ms);
        reset = 1;
        ThisThread::sleep_for(10ms);
        
        // Check version
        uint8_t version = read_register(REG_VERSION);
        serial_printf("SX1272 version: 0x%02X\r\n", version);
        
        // Set LoRa mode
        write_register(REG_OP_MODE, MODE_LONG_RANGE_MODE | MODE_SLEEP);
        ThisThread::sleep_for(10ms);
        
        // Set standby mode
        write_register(REG_OP_MODE, MODE_LONG_RANGE_MODE | MODE_STDBY);
        ThisThread::sleep_for(10ms);
        
        // Basic configuration
        write_register(REG_FIFO_TX_BASE_ADDR, 0x80);
        write_register(REG_FIFO_RX_BASE_ADDR, 0x00);
        write_register(REG_LNA, 0x23);
        write_register(REG_MODEM_CONFIG_3, 0x04);
        write_register(REG_SYNC_WORD, 0x12);
        write_register(REG_DIO_MAPPING_1, 0x00);
        write_register(REG_IRQ_FLAGS, 0xFF);
        
        serial_printf("SX1272 initialized\r\n");
    }
    
    void write_register(uint8_t addr, uint8_t data) {
        nss = 0;
        spi.write(addr | 0x80);
        spi.write(data);
        nss = 1;
    }
    
    uint8_t read_register(uint8_t addr) {
        nss = 0;
        spi.write(addr & 0x7F);
        uint8_t data = spi.write(0x00);
        nss = 1;
        return data;
    }
    
    void read_fifo(uint8_t* data, uint8_t size) {
        write_register(REG_FIFO_ADDR_PTR, read_register(REG_FIFO_RX_CURRENT_ADDR));
        nss = 0;
        spi.write(REG_FIFO & 0x7F);
        for (int i = 0; i < size; i++) {
            data[i] = spi.write(0x00);
        }
        nss = 1;
    }
    
    void set_frequency(uint32_t freq) {
        uint64_t frf = ((uint64_t)freq << 19) / 32000000;
        write_register(REG_FRF_MSB, (uint8_t)(frf >> 16));
        write_register(REG_FRF_MID, (uint8_t)(frf >> 8));
        write_register(REG_FRF_LSB, (uint8_t)(frf >> 0));
    }
    
    void set_spreading_factor(uint8_t sf) {
        if (sf < 6) sf = 6;
        if (sf > 12) sf = 12;
        
        uint8_t config2 = read_register(REG_MODEM_CONFIG_2);
        config2 = (config2 & 0x0F) | ((sf << 4) & 0xF0);
        write_register(REG_MODEM_CONFIG_2, config2);
        
        if (sf == 6) {
            write_register(REG_DETECTION_OPTIMIZE, 0xC5);
            write_register(REG_DETECTION_THRESHOLD, 0x0C);
        } else {
            write_register(REG_DETECTION_OPTIMIZE, 0xC3);
            write_register(REG_DETECTION_THRESHOLD, 0x0A);
        }
    }
    
    void configure_radio(uint32_t frequency, uint8_t sf) {
        write_register(REG_OP_MODE, MODE_LONG_RANGE_MODE | MODE_STDBY);
        
        set_frequency(frequency);
        set_spreading_factor(sf);
        
        // 125kHz bandwidth, CR 4/5
        write_register(REG_MODEM_CONFIG_1, 0x72);
        
        // Enable CRC
        uint8_t config2 = read_register(REG_MODEM_CONFIG_2);
        config2 |= 0x04;
        write_register(REG_MODEM_CONFIG_2, config2);
        
        write_register(REG_PREAMBLE_MSB, 0x00);
        write_register(REG_PREAMBLE_LSB, 0x08);
        write_register(REG_PAYLOAD_LENGTH, 0xFF);
        write_register(REG_IRQ_FLAGS, 0xFF);
    }
    
    void start_rx_continuous() {
        write_register(REG_OP_MODE, MODE_LONG_RANGE_MODE | MODE_RXCONTINUOUS);
    }
    
    void on_dio0_rise() {
        packet_received = true;
    }
    
    void start_sniffing() {
        running = true;
        packet_received = false;
        
        serial_printf("Starting LoRa packet sniffer...\r\n");
        serial_printf("Monitoring %d channels with %d SFs\r\n", 
                  frequencies.size(), spreading_factors.size());
        
        while (running) {
            sweep_channels();
        }
    }
    
    void sweep_channels() {
        for (current_sf_index = 0; current_sf_index < spreading_factors.size(); current_sf_index++) {
            for (current_freq_index = 0; current_freq_index < frequencies.size(); current_freq_index++) {
                if (!running) return;
                
                configure_radio(frequencies[current_freq_index], spreading_factors[current_sf_index]);
                start_rx_continuous();
                
                Timer timeout;
                timeout.start();
                packet_received = false;
                
                while (!packet_received && std::chrono::duration_cast<std::chrono::milliseconds>(timeout.elapsed_time()).count() < 200) {
                    if (!running) return;
                    ThisThread::sleep_for(1ms);
                }
                
                if (packet_received) {
                    process_received_packet();
                }
            }
        }
    }
    
    void process_received_packet() {
        uint8_t irq_flags = read_register(REG_IRQ_FLAGS);
        
        if (irq_flags & IRQ_RX_DONE_MASK) {
            LoRaPacket packet;
            packet.timestamp = time(NULL);
            packet.frequency = frequencies[current_freq_index];
            packet.sf = spreading_factors[current_sf_index];
            packet.crc_error = (irq_flags & IRQ_PAYLOAD_CRC_ERROR_MASK) != 0;
            
            packet.payload_size = read_register(REG_RX_NB_BYTES);
            packet.rssi = read_register(REG_PKT_RSSI_VALUE) - 137;
            int8_t snr_raw = read_register(REG_PKT_SNR_VALUE);
            packet.snr = snr_raw / 4;
            
            if (packet.payload_size > 0 && packet.payload_size <= 255) {
                read_fifo(packet.payload, packet.payload_size);
                parse_lorawan_header(packet);
                packet_log.push_back(packet);
                log_packet(packet);
            }
        }
        
        write_register(REG_IRQ_FLAGS, 0xFF);
    }
    
    void parse_lorawan_header(LoRaPacket& packet) {
        if (packet.payload_size < 1) return;
        
        uint8_t mhdr = packet.payload[0];
        packet.mtype = (mhdr >> 5) & 0x07;
        packet.is_join_request = (packet.mtype == 0x00);
        
        if (!packet.is_join_request && packet.payload_size >= 5) {
            packet.dev_addr = (packet.payload[4] << 24) |
                             (packet.payload[3] << 16) |
                             (packet.payload[2] << 8) |
                             packet.payload[1];
        } else {
            packet.dev_addr = 0;
        }
    }
    
    void log_packet(const LoRaPacket& packet) {
        serial_printf("PKT: Time=%lu Freq=%lu SF=%d RSSI=%d SNR=%d Size=%d ",
                  packet.timestamp, packet.frequency, packet.sf, 
                  packet.rssi, packet.snr, packet.payload_size);
        
        if (packet.crc_error) serial_printf("CRC_ERR ");
        
        if (packet.is_join_request) {
            serial_printf("Type=JOIN_REQ ");
        } else {
            serial_printf("Type=DATA DevAddr=%08lX ", packet.dev_addr);
        }
        
        serial_printf("Payload=");
        for (int i = 0; i < packet.payload_size; i++) {
            serial_printf("%02X", packet.payload[i]);
        }
        serial_printf("\r\n");
    }
    
    void stop_sniffing() {
        running = false;
        write_register(REG_OP_MODE, MODE_LONG_RANGE_MODE | MODE_SLEEP);
        serial_printf("Sniffer stopped\r\n");
    }
    
    void print_statistics() {
        serial_printf("\r\n=== STATISTICS ===\r\n");
        serial_printf("Total packets: %d\r\n", packet_log.size());
        
        int join_requests = 0;
        int data_packets = 0;
        int crc_errors = 0;
        
        for (size_t i = 0; i < packet_log.size(); i++) {
            if (packet_log[i].is_join_request) join_requests++;
            else data_packets++;
            if (packet_log[i].crc_error) crc_errors++;
        }
        
        serial_printf("Join requests: %d\r\n", join_requests);
        serial_printf("Data packets: %d\r\n", data_packets);
        serial_printf("CRC errors: %d\r\n", crc_errors);
    }
};

int main() {
    const char* msg = "SX1272 LoRa Packet Sniffer\r\n";
    pc.write(msg, strlen(msg));
    msg = "Commands: s=start, q=quit, t=stats\r\n\r\n";
    pc.write(msg, strlen(msg));
    
    SX1272LoRaSniffer sniffer;
    
    char cmd;
    while (true) {
        const char* prompt = "> ";
        pc.write(prompt, strlen(prompt));
        
        pc.read(&cmd, 1);
        
        char echo[4] = {cmd, '\r', '\n', '\0'};
        pc.write(echo, 3);
        
        switch (cmd) {
            case 's':
                sniffer.start_sniffing();
                break;
            case 'q':
                sniffer.stop_sniffing();
                return 0;
            case 't':
                sniffer.print_statistics();
                break;
            default:
                {
                    const char* unknown = "Unknown command\r\n";
                    pc.write(unknown, strlen(unknown));
                }
                break;
        }
    }
    
    return 0;
}
