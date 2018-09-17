# AMD-HyperForensics
A volatility plugin to analyse AMD-v hypervisors.  

## Installation
To be able to use this plugin to locate hypervisors and extract fields of the virtual machine control block you need to move the
```plugin/hypervisors``` folder to ```volatility-base-dir/volatility/plugins/```  

## Usage
After installation, you will be able to see the plugin ```amdhyperls``` using ```volatility --info```. The plugin offers
two modes of operation:  
- Conservative: This mode will check for a conservative signature of the VMCB. Will possible find false-positives.  
- Agressive: This mode will also check for bits that shouldn't change in a normal hypervisor. Will reduce significantly the number
of false-positives, but can be bypassed by malicious hypervisors.  

The conservative mode is the default, to search for hypervisors using AMD-v in a dump you simply need to call the plugin passing
the memory file as argument: ```volatility amdhyperls -f <Memory-Dump>```  

To use the agressive mode, you need to specify the option ```-a``` or ```--agressive```.  

It's also possible to enable verbose with ```-v``` or ```--verbose```, this will print the field of the VMCB with the respective
values.

## Introspection
The instrospection through volatility plugin is not working properly yet. But it's possible to analyze and check the guest memory
through manual introspection. The manual instrospection script will translate Guest Virtual/Physical Addresses to Host Physical
Addresses through Nested Paging Table.  

To see the ```_KUSER_SHARED_DATA``` of a 32-bit windows XP guest through manual introspection you need to:  
```python2.7 translator.py -f <Memory-Dump> --gva 0x7ffe0000 --gcr3 <Guest CR3 from VMCB> --nptp <N_CR3 from VMCB>```  
The output will be the host physical address mapped from the Guest Virtual Address.
