# keyhelper - unnecessary SSH-key manager mainly for my pleasure 

### Installation 
```
cargo install keyhelper
```

<details>
<summary> 
more </summary> 
  
#### Potential Dependencies:
- [Cargo & Rust:](https://doc.rust-lang.org/cargo/getting-started/installation.html)
   
- [Git for Windows](https://gitforwindows.org/)
  

#### Alternative Method
```
git clone https://github.com/nrdrch/keyhelper.git
```
```
cd keyhelper
```
```
cargo build --release
```
- Preferably move the executable from target/release into a directory in your 'Path' enviorment variable for easy execution.

</details>

------------------
| **Option**       | **Description**    | **Example**   |
| :---:        | :---          | :---     |
| -n KeyName |Create SSH-Key and name it | keyhelper -n pi         |     
| -p PassPhrase | Remove SSH-Key by name | keyhelper -n pi -p your-passphrase (optional) |
| -rm KeyName | Remove SSH-Key by name | keyhelper -rm pi        |
| -l          | List files in .ssh | keyhelper -l     |
| -c KeyName User@IP | Copy SSH Key to remote host    | keyhelper -c pi pi@192.168.178.40   |
---------

