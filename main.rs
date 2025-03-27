use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex;
use std::str;

fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(input)
}

fn reverse_string(input: &str) -> String {
    input.chars().rev().collect()
}

fn leet(input: &str) -> String {
    input.replace('o', "0")
}

fn decrypt_aes_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(ciphertext).unwrap()
}

fn decode_cheat_code(encoded: &str) -> Vec<u8> {
    let base64_decoded = base64_decode(encoded).unwrap();
    let hex_decoded = hex::decode(str::from_utf8(&base64_decoded).unwrap()).unwrap();
    let reversed = reverse_string(str::from_utf8(&hex_decoded).unwrap());
    leet(&reversed).into_bytes()
}

fn decode_flag(cheat_code: &str, iv: &str, encoded: &str) -> String {
    let key = decode_cheat_code(cheat_code);
    let iv_bytes = decode_cheat_code(iv);
    let ciphertext = hex::decode(encoded).unwrap();
    let plaintext = decrypt_aes_cbc(&key, &iv_bytes, &ciphertext);
    String::from_utf8(plaintext).unwrap()
}

fn main() {

    let boom = r#"
                ##           #                                                                      
                 %#       +%##                                                                      
                  %       %+% #                                                                     
                  *%      %@#%                                                                      
             %%  %=#%    *%%@                                                                       
               %% %#%+ %%- *                                                                        
                 #%#%% %%# %@                                                                       
                   %%=##@-=@@ %#@@@%%##%%@@@@%=                                                     
                 @@%%#=*##%=+#%%#            #%@@%                                                  
                   *%+@****@*@%*                %@@#                                                
           ##%#%@%###%-@%%@=@##*#%#              #@@%                                               
            %%#@%*%##%%%%%%%@+%%#%%*              @@@@                                              
               *@+  #@ *#%% %=  %%  *%             @@@@                                             
                      #%@%@*                       @@@@                                             
                      @ @ =@                   =***@@@@*                                            
                        %                   @+=*##*=--*%@                                           
                        %                  @@@@@@@@@@@@@+-%*                                        
                                          #@@%%%%@@@@@@@@@#+%                                       
                                      %#++*%@@@@@@%*=:+@@@@@@                      %%               
                                    @@@@@@@@@@@@@@@@@@@@%#@@*                    #@*                
                                  #@@@@@@@@@@@@@@@@@@@@@@@@@@                  %@@                  
                                +@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                %%%                   
*%                             *@@@#.:@@@@@@@@@@@@@@@@@@@@@@@@@             #%%%                    
  %%#                          @@@#...=@@@@@@@@@@@@@@@@@@@@@#@@%          %%#%%                     
     %@*                      *@@@-...#@@@@@@@@@@@@@@@@@@@%#%@@@*%@#.:@*%%##%*                      
       *@@@                   @@@@....%@@@@@@@@@@@@@@@@@%###%@@%......#@@%#%@                       
         =#@%%                @@@@....%@@@@@@@@@@@@@@@%#@%#%#@@@.......@@%##                        
            #%#%@%            @@@@:...%#@@@@@@@@@@@@@*.....+@@@@:......-@@%                         
              #%###%%%        %@@@#..=%###%@@@@@%###%-......-@@#-..+:...*@%                         
                 @####@%@@#    @@@@#@###########@+.#@%.......:@@%..-@....@@#                        
                  *@####%@%###%%%%############%+.....=+........@@...@#...-@@@*   =#@#**+            
                    %@#####@#@#####%@@@%####%@#.......%...=*....@=..*@:...*@@#####@@                
                      #######@*+%@%.....=@%@+*+..@@@%.:%...##...:%..:@@....@@%#%%                   
                       %%%%@@@%@*#........%@*#+.:@@*+*.+....@%.......@@*...:@@%                     
                      #@:.....@@@@...@@@*..#@%+.:@@++#..@...=@@......%@@=...#@@                     
                    %..........%@@-..@@*+%..%@%..@@*+#=.-=...%@@.....:@@@..:=@@%                    
                    +%...-%@#...@@#..%@#++%..@@:.-@%+#=..@...:@@@:....@@@@@@@@@%                    
                     %#..:@%#+..*@@-.:@@++*:.-@#..*@#%...@+...=@@%=*@@@@@#######%@##                
                      *+..=%=...%@@@..-@@++%..%@*.......#@@:.:*@@#+*%%*+*%@@%%%######%%%@+          
                       #-.........*@@...@@%:..*@@%.....-@@%%@@@@@*+%%##########%@@%#+@@@@++#%@@@@#* 
                    %%%#@:....=#:..=@@-.......#@@+#%**@@@%++++++++%#########@#                      
                     ##*@@...@%#%:..%@@%:....+@@%++++++++++*%@@@%*%########@                        
                         %#..:@%%....@@@+#@@@@%#++++++++++*%###############%                        
                         %%*.........@@@++++++++++++++++++#%####%%@%%@%@%##@                        
                        *%#%:......+@@%%%%%++++++++++#@##%@@###@           @%                       
                       %####@..=%@%#########*%%%%+++%##########@                                    
                    =%####@#%@%############@#####@+%###########*                                    
                  %%%##@@@#######################@######@@@@@%#@                                    
                #@##@@###%@%%##      *%##########@@###@+      *@*                                   
             %%%####%@#                %#%@   %%#@##%%                                              
           %%##%%@*                    %%      %#@#%%                                               
        %@#%%#                        %        +@###                                                
     #@@@#                                      @#@                                                 
  #@%#                                          @#@                                                 
%#                                              @@                                                  
                                                @+                                                  
                                               =@                                                   
                                               %@                                                   
                                               @+                                                   
"#;

    let cheat_code = "NDAyMTMzMzIzMTZiNmU1NTY4NDMzMzZjNjI3NTZmNDQ=";
    let iv = "MzEzNjM3MzgzOTM2MzczODM5MzMzMjM2MzEzNzM5Mzg=";
    let flag = "52db28b8e142ccd5fb3bb1002ac93ac8d78a8b837b4bdf2e2e3fec8f25f918cfa0287565a7d39c881cffd5ed4d98d219";

    let input = std::env::args()
        .nth(1)
        .expect("no input given");

    let cheat_code_decoded = String::from_utf8(decode_cheat_code(cheat_code)).unwrap();

    let count = if input == cheat_code_decoded {
        println!("🎉 Cheat Code activated! 5 BIG BOOMs incoming!");
        5
    } else {
        match input.parse::<u32>() {
            Ok(n) if (1..=4).contains(&n) => n,
            _ => {
                eprintln!("That's not a valid number of BOOOOOOMS (must be 1-4). Using 1 BOOM by default.");
                1
            }
        }
    };

    println!("We're sorry to hear about your friend who passed away... HE GETS {:?} BIG BOOOOOM(S)!!!!!", count);

    for _ in 0..count {
        println!("{}", boom);
    }

    if input == cheat_code_decoded {
        println!("{}", decode_flag(cheat_code, iv, flag));
    }

    println!("We're all boomed out, time to recharge with a chicken bake!");
}
