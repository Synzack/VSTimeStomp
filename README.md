# VSTimeStomp
Hex editor to modify the file header and debug directory timestamps in PE files generated by the Visual Studio .NET Framework.

When I created Visual Studio Console Apps using the .NET Framework, I would get timestamps in the PE Headers of the compiled file that were way in the future. This caused AV/EDR to mark the file as more suspicious and in some cases, block execution.

![image](https://user-images.githubusercontent.com/51035066/86117938-edc58c80-ba9d-11ea-9194-8b74f51961f4.png)
![image](https://user-images.githubusercontent.com/51035066/86117978-00d85c80-ba9e-11ea-95a2-996ab77cef0f.png)
![image](https://user-images.githubusercontent.com/51035066/86118012-0b92f180-ba9e-11ea-9eac-b864c49f92d5.png)

Since I couldn't find a free PE editor that would modify both of these timestamps, I decided to create this script. It will take an input file, modify the PE timestamps and output a new file, while leaving the original untouched. 

The default code is to change the timestamp to a random date between 1/3/2016 2:30 PM UTC and 12/15/2018 2:30 PM UTC. This can be modified in the script itself.

## Usage:
python vsTimestomp.py [inputfile] [outputfile]

![image](https://user-images.githubusercontent.com/51035066/86118041-16e61d00-ba9e-11ea-9b86-296922f1f6b9.png)
![image](https://user-images.githubusercontent.com/51035066/86118071-206f8500-ba9e-11ea-82b0-b561291f0357.png)
![image](https://user-images.githubusercontent.com/51035066/86118097-2a918380-ba9e-11ea-81da-3e3454cc3e42.png)
