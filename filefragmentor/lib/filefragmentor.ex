defmodule FileFragmentor do
  @moduledoc """
  Documentation for FileFragmentor.
  """
  import AES256

  def gen_key(password) do
    :crypto.hash(:sha256, password) |> Base.encode64
  end

  # aes encrypt a given chunk with provided password
  def frag_encrypt(fragment, hashkey) do
    IO.puts("[Encrypting] - frag[?]")
    iv = String.slice(hashkey, -16..-1)
    [iv: iv, ciphertext: ciphertext] = encrypt(fragment, hashkey, iv)
    IO.inspect(to_string(iv))
    ciphertext
  end

  # sha256 hash (aes_key + seqID)
  def frag_hmac({fragment, seq_id}, hashkey) do
    IO.puts("[HMAC] - frag[#{seq_id}")
    hmac = :crypto.hash(:sha256, hashkey <> <<seq_id>>) |> to_string
    {fragment <> hmac, seq_id}
  end

  # format and write out fragment to disk
  def write_out({fragment, seq_id}) do
    IO.puts("[Write-Out] - frag[#{seq_id}")
    {:ok, file} = File.open "DEBUG/abc_#{seq_id}", [:write]
    IO.binwrite file, fragment
  end

  # evenly distribute file bytes over fragments
  def merge_rem(remainders, last, last), do: [ Enum.join(remainders) ]
  def merge_rem([ head | tail ], count, frag_count) do
    [ new_head | new_tail ] = tail
    [ head ] ++ merge_rem([ new_head | new_tail ], count + 1, frag_count)
  end

  # fragment file into n parts
  def fragment(password, fpath, frag_count) do
    %{size: size} = File.stat! fpath
    # todo: throw error if frag_count > size
    chunksize = div(size, frag_count)
    hashkey = gen_key(password)
    File.stream!(fpath, [ ], chunksize)
      |> Enum.to_list
      |> merge_rem(1, frag_count)
      |> Enum.map(fn(chunk) -> frag_encrypt(chunk, hashkey) end)
      |> Stream.with_index
      |> Enum.map(fn(frag) -> frag_hmac(frag, hashkey) end)
      |> Enum.each(fn(frag) -> write_out(frag) end)
  end

  # reassemble n parts into single file
  def reassemble(_, _) do
    IO.puts("reassemble")
  end

end