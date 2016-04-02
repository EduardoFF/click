N=$1


for (( K = 1 ; K <= $N ; K=$K+1 ))
do 
  echo "doing rnp_ns3_n$K.click"
  cp rnp_ns3_n0.click rnp_ns3_n$K.click 
  sed -i "s/172.16.0.1/172.16.0.$((K+1))/g" rnp_ns3_n$K.click 
  sed -i "s/00:01/00:$(printf %02d $((K+1)))/g" rnp_ns3_n$K.click 
  sed -i "s/n0/n$(printf %02d $((K+1)))/g" rnp_ns3_n$K.click 
done
echo "Done!"

