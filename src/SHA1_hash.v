// Paul Do
// Surya Manchikanti
//ECE111 WI16

module SHA1_hash (
	clk, 		
	nreset, 	
	start_hash,
	message_addr,	
	message_size, 	
	hash, 		
	done, 		
	port_A_clk,
    port_A_data_in,
    port_A_data_out,
	port_A_addr,
	port_A_we
	);

input	clk;
input	nreset;
// Initializes the sha1 module

input	start_hash;
// Tells sha1 to start encoding the given frame

input 	[31:0] message_addr;
// Starting address of the plaintext frame
// i.e., specifies from where SHA1 must read the plaintext frame

input	[31:0] message_size;
// Length of the plain text in bytes

input   [31:0] port_A_data_out;
// read data from the dpsram (plaintext)

output  [31:0] port_A_data_in;
// write data to the dpsram (ciphertext)

output  [15:0] port_A_addr;
// address of dpsram being read/written

output  port_A_clk;
// clock to dpsram (drive this with the input clk)

output  port_A_we;
// read/write selector for dpsram

output	[159:0] hash;
// hash output

output	done; // done is a signal to indicate that encryption of the frame is complete

assign port_A_clk = clk;

//wire message_size;
//wire message_addr;
reg done;

parameter IDLE = 4'b0000;
parameter BUFFER = 4'b0001;
parameter step0read = 4'b0010;
parameter step0gen = 4'b1000;
parameter step16 = 4'b1001;
parameter step20 = 4'b0011;
parameter step40 = 4'b0100;
parameter step60 = 4'b0101;
parameter step80 = 4'b0110;
parameter WRAPUP = 4'b0111;

reg [15:0] current_addr;
reg [31:0] remaining_msg_size;
reg [31:0] padding_bits;
//reg [31:0] total_size;



reg [31:0] Wtarray [16:0];


reg [31:0] A;
reg [31:0] B;
reg [31:0] C;
reg [31:0] D;
reg [31:0] E;

reg [31:0] H0;
reg [31:0] H1;
reg [31:0] H2;
reg [31:0] H3;
reg [31:0] H4;

reg [31:0] w;  // word + padded "100..." (if not full word)
reg [31:0] Wt; // used for stepfunction calculation
reg [31:0] w1; // word in little-endian
reg [31:0] F;
reg [31:0] T;
reg [3:0] state;
reg [31:0] k;
reg [7:0] t;

reg [4:0] i;

assign port_A_we = 0;
assign port_A_data_in = 0;
assign port_A_addr = current_addr;
assign hash = {H0[31:0], H1[31:0], H2[31:0], H3[31:0], H4[31:0]};


function [31:0] changeEndian;
	input [31:0] value;
	changeEndian = {value[7:0], value[15:8], value[23:16], value[31:24]};
endfunction	

function [31:0] calc_T;
	input [31:0] A_t;
	input [31:0] F_t;
	input [31:0] Wt_t;
	input [31:0] k_t;
	input [31:0] E_t;
	calc_T = ({A_t[26:0],A_t[31:27]} + F_t + Wt_t + k_t + E_t);
endfunction

function [31:0] calc_F;
	input [31:0] B_f;
	input [31:0] C_f;
	input [31:0] D_f;
	input [3:0] sel;
	
	case (sel)
	0: calc_F = (B & C) ^ (~B & D);
	1: calc_F = B^C^D;
	2: calc_F = (B & C) ^ (B & D) ^ (C & D);
	endcase
endfunction

always @(posedge clk or negedge nreset) begin
	if (!nreset) begin
		state <= IDLE;
		done <= 0;
		end
	else begin case (state)
		IDLE:
		begin
			if (start_hash) begin
				
				remaining_msg_size = message_size * 8;
				
				padding_bits = 545 - ((remaining_msg_size+65)%512);

//				padding_bits = padding_bits + 33; // plus 32 from mlength, + 1 "1"
				
				current_addr = message_addr [15:0];
				
				done = 0;

				t = 0;
				
				
				state = BUFFER;

				// init ABCDE
				A = 32'h67452301;
				B = 32'hefcdab89;
				C = 32'h98badcfe;
				D = 32'h10325476;
				E = 32'hc3d2e1f0;

				H0 = 32'h67452301;
				H1 = 32'hefcdab89;
				H2 = 32'h98badcfe;
				H3 = 32'h10325476;
				H4 = 32'hc3d2e1f0;
				
				k = 32'h5a827999;
			end
		end

		BUFFER:
		begin
			state <= step0read;
			current_addr = current_addr + 16'd4;
		end

		
		step0read:
		begin
			w1 = changeEndian(port_A_data_out);
			
			if (remaining_msg_size == 24) begin
				w = {w1[31:8], 8'b10000000};
				remaining_msg_size = 0;
				padding_bits = padding_bits - 8;
				state = step0gen;
			end
			else if (remaining_msg_size == 16) begin
				w = {w1[31:16], 16'b1000000000000000};
				remaining_msg_size = 0;
				padding_bits = padding_bits - 16;
				state = step0gen;
			end
			else if (remaining_msg_size == 8) begin
				w = {w1[31:24], 24'b100000000000000000000000};
				remaining_msg_size = 0;
				padding_bits = padding_bits - 24;
				state = step0gen;
			end
			else if (remaining_msg_size == 0) begin
				w = 32'b10000000000000000000000000000000;
				padding_bits = padding_bits - 32;
				state = step0gen;
			end
			else begin
				w = w1;
				remaining_msg_size = remaining_msg_size - 32;
			end
			
			Wtarray[t] = w;
			Wt = w;
			
			F = calc_F(B, C, D, 0);
//			F = (B & C) ^ (~B & D);
			
			T = calc_T(A, F, Wt, k, E);
			
//			T = ({A[26:0],A[31:27]} + F + Wt + k + E) % (32'hFFFFFFFF);
			
			E = D;
			D = C;
			C = {B[1:0],B[31:2]};
			B = A;
			A = T;
			
			t = t + 8'd1;
			
			if (t == 16) begin
				state = step16;
			end
			else begin
				current_addr = current_addr + 16'd4;
			end
			
		end
		
		step0gen:
		begin
			if (padding_bits == 0) begin
				w = message_size * 8;
			end
			else begin
				w = 32'b00000000000000000000000000000000;
				padding_bits = padding_bits - 32;
			end
			
			Wtarray[t] = w;
			Wt = w;

			F = calc_F(B, C, D, 0);			
//			F = (B & C) ^ (~B & D);
			
			T = calc_T(A, F, Wt, k, E);
//			T = ({A[26:0],A[31:27]} + F + Wt + k + E) % (32'hFFFFFFFF);
			
			E = D;
			D = C;
			C = {B[1:0],B[31:2]};
			B = A;
			A = T;
			
			t = t + 8'd1;
			
			if (t == 16) begin
				state = step16;
			end
		end
			
		
		step16:
		begin
			Wt = (Wtarray[0] ^ Wtarray[2] ^ Wtarray[8] ^ Wtarray[13]);
				
			Wtarray[16] = {Wt[30:0],Wt[31]};
				
			for(i = 5'd1; i < 5'd17; i=i+5'd1) begin
				Wtarray[i - 1] = Wtarray[i];
			end

			Wt = Wtarray[16];
			
			F = calc_F(B, C, D, 0);
//			F = (B & C) ^ (~B & D);
			
			T = calc_T(A, F, Wt, k, E);
//			T = ({A[26:0],A[31:27]} + F + Wt + k + E) % (32'hFFFFFFFF);
			
			E = D;
			D = C;
			C = {B[1:0],B[31:2]};
			B = A;
			A = T;
			
			t = t + 8'd1;
			
			if (t==20) begin
				state = step20;
				k = 32'h6ed9eba1;
			end
		end
		
		step20:
		begin
			Wt = (Wtarray[0] ^ Wtarray[2] ^ Wtarray[8] ^ Wtarray[13]);

			Wtarray[16] = {Wt[30:0],Wt[31]};
				
			for(i = 5'd1; i < 5'd17; i=i+5'd1) begin
				Wtarray[i - 1] = Wtarray[i];
			end

			Wt = Wtarray[16];

			F = calc_F(B, C, D, 1);
//			F = B^C^D;
			
			T = calc_T(A, F, Wt, k, E);
//			T = ({A[26:0],A[31:27]} + F + Wt + k + E) % (32'hFFFFFFFF);
			
			E = D;
			D = C;
			C = {B[1:0],B[31:2]};
			B = A;
			A = T;
			
			t = t + 8'd1;
			
			if (t==40) begin
				state = step40;
				k = 32'h8f1bbcdc;
			end
		end
		
		
		step40:
		begin
			Wt = (Wtarray[0] ^ Wtarray[2] ^ Wtarray[8] ^ Wtarray[13]);

			Wtarray[16] = {Wt[30:0],Wt[31]};
				
			for(i = 5'd1; i < 5'd17; i=i+5'd1) begin
				Wtarray[i - 1] = Wtarray[i];
			end

			Wt = Wtarray[16];

			F = calc_F(B, C, D, 2);			
//			F = (B & C) ^ (B & D) ^ (C & D);
			
			T = calc_T(A, F, Wt, k, E);
//			T = ({A[26:0],A[31:27]} + F + Wt + k + E) % (32'hFFFFFFFF);
			
			E = D;
			D = C;
			C = {B[1:0],B[31:2]};
			B = A;
			A = T;
			
			t = t + 8'd1;
			
			if (t==60) begin
				state = step60;
				k = 32'hca62c1d6;
			end
		end

		
		step60:
		begin
			Wt = (Wtarray[0] ^ Wtarray[2] ^ Wtarray[8] ^ Wtarray[13]);

			Wtarray[16] = {Wt[30:0],Wt[31]};
				
			for(i = 5'd1; i < 5'd17; i=i+5'd1) begin
				Wtarray[i - 1] = Wtarray[i];
			end

			Wt = Wtarray[16];
			
			F = calc_F(B, C, D, 1);
//			F = B ^ C ^ D;

			T = calc_T(A, F, Wt, k, E);
//			T = ({A[26:0],A[31:27]} + F + Wt + k + E) % (32'hFFFFFFFF);
			
			E = D;
			D = C;
			C = {B[1:0],B[31:2]};
			B = A;
			A = T;
			
			t = t + 8'd1;
			
			if (t==80) begin
				t = 0;
				k = 32'h5a827999;
				
				H0 = H0 + A;
				H1 = H1 + B;
				H2 = H2 + C;
				H3 = H3 + D;
				H4 = H4 + E;
				
				A = H0;
				B = H1;
				C = H2;
				D = H3;
				E = H4;
				
				if (padding_bits == 0) begin
					done = 1;
					state = IDLE;
				end
				else begin
					if (remaining_msg_size > 0) begin
						state = step0read;
						current_addr = current_addr+16'd4;
					end
					else begin
						state = step0gen;
					end
				end
			end
		end
		endcase
	end
end
endmodule
		

